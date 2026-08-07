package mesh

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// OktaUser is a simulated Okta directory profile correlated to a mesh identity.
type OktaUser struct {
	// OktaID is the fake Okta user id.
	OktaID string `json:"oktaId"`
	// Username is the mesh identity username.
	Username string `json:"username"`
	// Email is the fake corporate email.
	Email string `json:"email"`
	// Groups are the Okta group memberships.
	Groups []string `json:"groups"`
	// LastLogin is the fake last login timestamp.
	LastLogin time.Time `json:"lastLogin"`
	// CreatedAt is when the profile was created.
	CreatedAt time.Time `json:"createdAt"`
}

// OktaGhostCreator simulates Okta directory entries locally. Real Okta
// provisioning requires an org, so v2 simulates profiles in okta-ghosts.json.
type OktaGhostCreator struct {
	// File is the path to the okta-ghosts.json store.
	File string
}

// NewOktaGhostCreator returns a creator persisting to the given file.
func NewOktaGhostCreator(file string) *OktaGhostCreator {
	return &OktaGhostCreator{File: file}
}

// Create appends a fake Okta profile for a mesh identity and returns it.
func (o *OktaGhostCreator) Create(username string, idx int) (OktaUser, error) {
	prof := profilePool[idx%len(profilePool)]
	groups := groupPool[idx%len(groupPool)]

	user := OktaUser{
		OktaID:    "00u" + randomHex(10),
		Username:  username,
		Email:     prof.Email,
		Groups:    groups,
		LastLogin: time.Now().UTC().Add(-time.Duration(idx+1) * 24 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}

	users, err := o.read()
	if err != nil {
		return OktaUser{}, err
	}
	users = append(users, user)
	if err := o.write(users); err != nil {
		return OktaUser{}, err
	}
	return user, nil
}

func (o *OktaGhostCreator) read() ([]OktaUser, error) {
	data, err := os.ReadFile(o.File)
	if err != nil {
		if os.IsNotExist(err) {
			return []OktaUser{}, nil
		}
		return nil, fmt.Errorf("okta: read %s: %w", o.File, err)
	}
	users := []OktaUser{}
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("okta: parse %s: %w", o.File, err)
	}
	return users, nil
}

func (o *OktaGhostCreator) write(users []OktaUser) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(o.File, data, 0o600); err != nil {
		return err
	}
	return nil
}
