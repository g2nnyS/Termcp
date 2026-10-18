package sshconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/open-mcp-ai/termcp/internal/vault"
)

// ErrNotFound reports that a named ssh config does not exist. Callers can
// branch on it with errors.Is instead of matching the message.
var ErrNotFound = errors.New("not found")

// ErrReserved reports that a name denotes the built-in internal profile, which
// is virtual and cannot be deleted. It is a sentinel so a batch caller can turn
// it into its own per-name code without re-testing the name or restating the
// message that Delete already carries.
var ErrReserved = errors.New("reserved ssh config")

// Store manages dataDir/ssh_configs/<name>/config.toml for remote profiles.
// The built-in "internal" profile is virtual: it is never written to disk.
//
// When the data directory holds a vault (SetVault with an initialized
// vault.Vault), remote profiles live encrypted under vault/ssh_configs/
// instead: Save seals, Load opens, and the plaintext path is only a read
// fallback for not-yet-migrated profiles. The store never refuses plaintext
// operation on a vault-less data directory — a deployment without a vault
// behaves exactly as before.
type Store struct {
	dataDir   string
	mu        sync.Mutex
	temporary map[string][]byte // process-local profiles; guarded by mu
	onChange  atomic.Value      // func(), set via SetOnChange, called after Save/Delete/Rename
	vault     *vault.Vault      // nil until SetVault
}

// SetVault attaches the credential vault rooted at the same data directory.
// Called once at wiring time (main.go); the vault's lock state is consulted
// per operation, not cached.
func (s *Store) SetVault(v *vault.Vault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vault = v
}

// SetOnChange registers a callback fired after Save, Delete, or Rename succeeds.
func (s *Store) SetOnChange(fn func()) {
	s.onChange.Store(fn)
}

func (s *Store) notifyChange() {
	fn, _ := s.onChange.Load().(func())
	if fn != nil {
		fn()
	}
}

// NewStore returns a Store rooted at dataDir (always absolute path when Abs succeeds).
func NewStore(dataDir string) *Store {
	d := filepath.Clean(strings.TrimSpace(dataDir))
	if d == "" {
		d = "."
	}
	abs, err := filepath.Abs(d)
	if err != nil {
		abs = d
	}
	return &Store{dataDir: abs}
}

func (s *Store) root() string {
	return filepath.Join(s.dataDir, "ssh_configs")
}

// ConfigDir returns the directory containing config.toml for a named profile.
// For the virtual internal profile this path is not used for I/O.
func (s *Store) ConfigDir(name string) string {
	return filepath.Join(s.root(), name)
}

func (s *Store) configPath(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	return filepath.Join(s.root(), name, "config.toml"), nil
}

// Load reads and validates a named config.
// name "internal" is the built-in entry, optionally overridden by a stored
// internal/config.toml (see ParseInternalOverride).
func (s *Store) Load(name string) (*Entry, error) {
	name = strings.TrimSpace(name)
	if IsInternalName(name) {
		base := InternalEntry()
		data, err := os.ReadFile(s.internalOverridePath())
		if err != nil {
			if os.IsNotExist(err) {
				return base, nil // no override: the defaults ARE the profile
			}
			return nil, err
		}
		ent, err := ParseInternalOverride(data, base)
		if err != nil {
			// A broken override is reported, not silently ignored: falling back
			// to the defaults would run the session UNGATED after the user asked
			// for a gate, which is the one direction this must never fail.
			return nil, fmt.Errorf("internal profile override: %w", err)
		}
		return ent, nil
	}
	p, err := s.configPath(name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	data, inMemory := s.temporary[name]
	data = append([]byte(nil), data...)
	vt := s.vault
	s.mu.Unlock()
	if inMemory {
		return ParseAndValidate(data)
	}
	if vt != nil && vt.Exists() && vt.Has(name) {
		// A vaulted profile decrypts at load time; a locked vault fails the
		// load with vault.ErrLocked, which session_start surfaces as unlock
		// guidance rather than a dial error.
		plain, err := vt.Decrypt(name)
		if err != nil {
			return nil, err
		}
		return ParseAndValidate(plain)
	}
	data, err = os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("ssh config %q %w (use data-dir/ssh_configs/%s/config.toml)", name, ErrNotFound, name)
		}
		return nil, err
	}
	return ParseAndValidate(data)
}

// ReadRaw returns the raw config.toml bytes for a name.
//
// For the internal profile it returns the stored override when one exists and
// the built-in template otherwise, so the editor round-trips what is actually
// in effect rather than a constant it cannot change.
func (s *Store) ReadRaw(name string) ([]byte, error) {
	name = strings.TrimSpace(name)
	if IsInternalName(name) {
		data, err := os.ReadFile(s.internalOverridePath())
		if err == nil {
			return data, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		return InternalTemplate(), nil
	}
	p, err := s.configPath(name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	data, inMemory := s.temporary[name]
	data = append([]byte(nil), data...)
	vt := s.vault
	s.mu.Unlock()
	if inMemory {
		return data, nil
	}
	if vt != nil && vt.Exists() && vt.Has(name) {
		// ReadRaw feeds the operator's own edit form, so a vaulted profile
		// decrypts here when the vault is unlocked — the same trust the
		// operator's keyboard already has. Locked vaults answer ErrLocked.
		return vt.Decrypt(name)
	}
	data, err = os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if _, err := ParseAndValidate(data); err != nil {
		return nil, err
	}
	return data, nil
}

// List returns sorted config names: virtual "internal", temporary profiles,
// vaulted profiles, and profiles on disk. Vaulted names are visible while
// locked — the filename is the profile name by design.
// Leftover ssh_configs/internal/ directories are ignored.
func (s *Store) List() ([]string, error) {
	s.mu.Lock()
	vt := s.vault
	entries, err := os.ReadDir(s.root())
	if err != nil {
		if !os.IsNotExist(err) {
			s.mu.Unlock()
			return nil, err
		}
	}
	names := []string{"internal"}
	seen := map[string]bool{"internal": true}
	for name := range s.temporary {
		names = append(names, name)
		seen[name] = true
	}
	s.mu.Unlock()
	if vt != nil && vt.Exists() {
		vaulted, err := vt.List()
		if err != nil {
			return nil, err
		}
		for _, name := range vaulted {
			if !seen[name] {
				names = append(names, name)
				seen[name] = true
			}
		}
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		name := e.Name()
		if IsInternalName(name) || seen[name] {
			continue // disk leftover; virtual entry already listed
		}
		cfg := filepath.Join(s.root(), name, "config.toml")
		if st, err := os.Stat(cfg); err == nil && !st.IsDir() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// Save writes config for a name (validates first).
//
// The internal profile is saved as an override file that Load layers over the
// built-in defaults, so setting one field does not mean restating the rest.
func (s *Store) Save(name string, data []byte) error {
	return s.SaveWithOptions(name, data, false)
}

// SaveWithOptions stores a remote profile only in memory when temporary is true.
// Switching an existing profile between modes removes its previous copy.
func (s *Store) SaveWithOptions(name string, data []byte, temporary bool) error {
	if IsInternalName(name) {
		if temporary {
			return fmt.Errorf("internal profile cannot be temporary")
		}
		if _, err := ParseInternalOverride(data, InternalEntry()); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		p := s.internalOverridePath()
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return err
		}
		if err := writeFileAtomic(p, data); err != nil {
			return err
		}
		s.notifyChange()
		return nil
	}
	if _, err := ParseAndValidate(data); err != nil {
		return err
	}
	if err := ValidateName(name); err != nil {
		return err
	}
	p := filepath.Join(s.root(), name, "config.toml")

	// The mutex guards the temporary map and the collision check only; file
	// I/O runs unlocked because both writers finish with an atomic rename, so
	// a concurrent Save of the same name degrades to last-writer-wins instead
	// of a corrupted file.
	s.mu.Lock()
	if err := s.checkNameCollisionLocked(name, name); err != nil {
		s.mu.Unlock()
		return err
	}
	vt := s.vault
	useVault := vt != nil && vt.Exists()
	if temporary {
		if s.temporary == nil {
			s.temporary = make(map[string][]byte)
		}
		s.temporary[name] = append([]byte(nil), data...)
	}
	s.mu.Unlock()

	if temporary {
		// A temporary profile supersedes any disk or vaulted copy in Load
		// order; removing those copies keeps that unambiguous.
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		_ = os.Remove(filepath.Dir(p))
		if vt != nil {
			_ = vt.Delete(name)
		}
		s.notifyChange()
		return nil
	}
	if useVault {
		// Sealing replaces the plaintext file: leaving the TOML next to the
		// ciphertext would keep the secret one `cat` away from gone.
		if err := vt.Encrypt(name, data); err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		_ = os.Remove(filepath.Dir(p))
	} else {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return err
		}
		if err := writeFileAtomic(p, data); err != nil {
			return err
		}
	}
	s.mu.Lock()
	delete(s.temporary, name)
	s.mu.Unlock()
	s.notifyChange()
	return nil
}

// IsTemporary reports whether the profile exists only in this process.
func (s *Store) IsTemporary(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.temporary[name]
	return ok
}

func (s *Store) checkNameCollisionLocked(name, exclude string) error {
	for existing := range s.temporary {
		if existing != exclude && strings.EqualFold(existing, name) {
			return fmt.Errorf("config already exists: %s", existing)
		}
	}
	entries, err := os.ReadDir(s.root())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != exclude && strings.EqualFold(entry.Name(), name) {
			return fmt.Errorf("config already exists: %s", entry.Name())
		}
	}
	return nil
}

// internalOverridePath is where a stored internal-profile override lives. The
// name is dot-prefixed so the directory scan that builds the profile list skips
// it (that scan treats any dot-directory as private).
func (s *Store) internalOverridePath() string {
	return filepath.Join(s.root(), ".internal", "config.toml")
}

// writeFileAtomic writes data through a temp file and renames it into place, so
// a crash cannot leave a half-written config behind. The file is 0600: profiles
// hold credentials.
func writeFileAtomic(p string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-cfg-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, p); err != nil {
		return err
	}
	return nil
}

// Rename moves a remote config directory to a new validated name.
func (s *Store) Rename(oldName, newName string) error {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == newName {
		return nil
	}
	if IsInternalName(oldName) || IsInternalName(newName) {
		return fmt.Errorf("cannot rename reserved ssh config %q", "internal")
	}
	oldPath, err := s.configPath(oldName)
	if err != nil {
		return err
	}
	newPath, err := s.configPath(newName)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkNameCollisionLocked(newName, oldName); err != nil {
		return err
	}
	if data, ok := s.temporary[oldName]; ok {
		if _, exists := s.temporary[newName]; exists {
			return fmt.Errorf("config already exists: %s", newName)
		}
		if _, err := os.Stat(newPath); err == nil {
			return fmt.Errorf("config already exists: %s", newName)
		} else if !os.IsNotExist(err) {
			return err
		}
		s.temporary[newName] = data
		delete(s.temporary, oldName)
		s.notifyChange()
		return nil
	}

	// A vaulted profile moves by re-sealing under the new name; the vault's
	// ErrLocked passes straight through, since a rename is exactly where a
	// caller learns the vault must be unlocked first.
	if vt := s.vault; vt != nil && vt.Exists() && vt.Has(oldName) {
		if vt.Has(newName) {
			return fmt.Errorf("config already exists: %s", newName)
		}
		plain, err := vt.Decrypt(oldName)
		if err != nil {
			return err
		}
		if err := vt.Encrypt(newName, plain); err != nil {
			return err
		}
		if err := vt.Delete(oldName); err != nil {
			return err
		}
		// A stale plaintext copy under the old name must not survive the move.
		_ = os.Remove(oldPath)
		_ = os.Remove(filepath.Dir(oldPath))
		s.notifyChange()
		return nil
	}

	oldDir := filepath.Dir(oldPath)
	newDir := filepath.Dir(newPath)
	if st, err := os.Stat(oldPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("ssh config %q %w", oldName, ErrNotFound)
		}
		return err
	} else if st.IsDir() {
		return fmt.Errorf("ssh config %q is not a file", oldName)
	}
	// Case-insensitive collision check (Windows/macOS).
	entries, err := os.ReadDir(s.root())
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != oldName && strings.EqualFold(e.Name(), newName) {
			return fmt.Errorf("config already exists: %s", filepath.Join(s.root(), e.Name(), "config.toml"))
		}
	}
	if err := os.Rename(oldDir, newDir); err != nil {
		return err
	}
	s.notifyChange()
	return nil
}

// Delete removes a remote config; the virtual internal profile cannot be deleted.
func (s *Store) Delete(name string) error {
	if IsInternalName(name) {
		return fmt.Errorf("cannot delete reserved ssh config %q: %w", name, ErrReserved)
	}
	p, err := s.configPath(name)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	s.mu.Lock()
	vt := s.vault
	delete(s.temporary, name)
	s.mu.Unlock()
	if vt != nil && vt.Exists() {
		_ = vt.Delete(name)
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(dir)
	s.notifyChange()
	return nil
}
