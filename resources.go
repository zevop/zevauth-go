package zevauth

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// User is an end user as the backend API returns it.
type User struct {
	ID             string         `json:"id"`
	Email          *string        `json:"email"`
	EmailVerified  bool           `json:"emailVerified"`
	Username       *string        `json:"username"`
	Phone          *string        `json:"phone"`
	PhoneVerified  bool           `json:"phoneVerified"`
	FirstName      *string        `json:"firstName"`
	LastName       *string        `json:"lastName"`
	ImageURL       *string        `json:"imageUrl"`
	PublicMetadata map[string]any `json:"publicMetadata"`
	Status         string         `json:"status"`
	MFAEnabled     *bool          `json:"mfaEnabled,omitempty"`
	LastSignInAt   *string        `json:"lastSignInAt"`
	CreatedAt      string         `json:"createdAt"`
}

// Page is one page of a list (contract §3.3). Next is the cursor for the
// following page's After.
type Page[T any] struct {
	Data       []T     `json:"data"`
	HasMore    bool    `json:"hasMore"`
	Next       *string `json:"next"`
	TotalCount int     `json:"totalCount"`
}

// UsersService is Client.Users.
type UsersService struct{ c *Client }

// ListUsersParams filter Users.List. Metadata pairs are ANDed.
type ListUsersParams struct {
	Limit    int
	After    string
	Query    string
	Metadata map[string]string
}

func (p ListUsersParams) values() url.Values {
	q := url.Values{}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.After != "" {
		q.Set("after", p.After)
	}
	if p.Query != "" {
		q.Set("query", p.Query)
	}
	// The API reads the bracketed form; built here rather than left to a
	// serialiser that spells nested values its own way.
	for k, v := range p.Metadata {
		q.Set("metadata["+k+"]", v)
	}
	return q
}

// List returns one page of users.
func (s *UsersService) List(ctx context.Context, params ListUsersParams) (*Page[User], error) {
	var page Page[User]
	err := s.c.do(ctx, http.MethodGet, "/v1/users", params.values(), nil, &page)
	return &page, err
}

// Iter walks every user matching params, fetching pages as it goes:
//
//	it := client.Users.Iter(ctx, zevauth.ListUsersParams{})
//	for it.Next() {
//		fmt.Println(it.User().ID)
//	}
//	if err := it.Err(); err != nil { … }
func (s *UsersService) Iter(ctx context.Context, params ListUsersParams) *UserIterator {
	return &UserIterator{ctx: ctx, s: s, params: params}
}

// UserIterator follows Next until HasMore is false.
type UserIterator struct {
	ctx    context.Context
	s      *UsersService
	params ListUsersParams
	buf    []User
	cur    User
	done   bool
	err    error
}

// Next advances to the next user, fetching a page when needed.
func (it *UserIterator) Next() bool {
	for len(it.buf) == 0 {
		if it.done || it.err != nil {
			return false
		}
		page, err := it.s.List(it.ctx, it.params)
		if err != nil {
			it.err = err
			return false
		}
		it.buf = page.Data
		if page.HasMore && page.Next != nil && *page.Next != "" {
			it.params.After = *page.Next
		} else {
			it.done = true
		}
	}
	it.cur, it.buf = it.buf[0], it.buf[1:]
	return true
}

// User is the current user.
func (it *UserIterator) User() User { return it.cur }

// Err is the error that stopped iteration, if any.
func (it *UserIterator) Err() error { return it.err }

// Get returns one user.
func (s *UsersService) Get(ctx context.Context, userID string) (*User, error) {
	var u User
	err := s.c.do(ctx, http.MethodGet, "/v1/users/"+escape(userID), nil, nil, &u)
	return &u, err
}

// CreateUserParams are the fields for Users.Create. Empty fields are
// omitted.
type CreateUserParams struct {
	Email           string         `json:"email"`
	Password        string         `json:"password,omitempty"`
	FirstName       string         `json:"firstName,omitempty"`
	LastName        string         `json:"lastName,omitempty"`
	EmailVerified   *bool          `json:"emailVerified,omitempty"`
	PublicMetadata  map[string]any `json:"publicMetadata,omitempty"`
	PrivateMetadata map[string]any `json:"privateMetadata,omitempty"`
}

// Create creates a user.
func (s *UsersService) Create(ctx context.Context, params CreateUserParams) (*User, error) {
	var u User
	err := s.c.do(ctx, http.MethodPost, "/v1/users", nil, params, &u)
	return &u, err
}

// Update changes the fields present in params. Map values are sent as
// given, so nil clears a field: {"firstName": nil}.
func (s *UsersService) Update(ctx context.Context, userID string, params map[string]any) (*User, error) {
	var u User
	err := s.c.do(ctx, http.MethodPatch, "/v1/users/"+escape(userID), nil, params, &u)
	return &u, err
}

// SetBlockedResult is what Users.SetBlocked returns.
type SetBlockedResult struct {
	User            User `json:"user"`
	SessionsRevoked int  `json:"sessionsRevoked"`
}

// SetBlocked blocks or unblocks a user. Blocking ends their sessions.
func (s *UsersService) SetBlocked(ctx context.Context, userID string, blocked bool) (*SetBlockedResult, error) {
	var out SetBlockedResult
	err := s.c.do(ctx, http.MethodPost, "/v1/users/"+escape(userID)+"/blocked", nil, map[string]bool{"blocked": blocked}, &out)
	return &out, err
}

// RevokeSessions ends every session the user has and returns how many.
func (s *UsersService) RevokeSessions(ctx context.Context, userID string) (int, error) {
	var out struct {
		SessionsRevoked int `json:"sessionsRevoked"`
	}
	err := s.c.do(ctx, http.MethodPost, "/v1/users/"+escape(userID)+"/sessions/revoke", nil, nil, &out)
	return out.SessionsRevoked, err
}

// ResetMFAOptions are the options for Users.ResetMFA.
type ResetMFAOptions struct {
	// RevokeSessions also signs the user out everywhere. Defaults to
	// false, to match the API.
	RevokeSessions bool
}

// ResetMFA removes the user's second factors, for support.
func (s *UsersService) ResetMFA(ctx context.Context, userID string, opts ResetMFAOptions) error {
	var q url.Values
	if opts.RevokeSessions {
		q = url.Values{"revokeSessions": {"true"}}
	}
	return s.c.do(ctx, http.MethodDelete, "/v1/users/"+escape(userID)+"/mfa", q, nil, nil)
}

// Delete deletes a user.
func (s *UsersService) Delete(ctx context.Context, userID string) error {
	return s.c.do(ctx, http.MethodDelete, "/v1/users/"+escape(userID), nil, nil, nil)
}

// Organization is an organization as the backend API returns it.
type Organization struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Slug           *string `json:"slug"`
	ImageURL       *string `json:"imageUrl"`
	PublicMetadata any     `json:"publicMetadata"`
	MaxMembers     *int    `json:"maxMembers"`
	RequireMFA     *bool   `json:"requireMfa,omitempty"`
	CreatedAt      string  `json:"createdAt"`
}

// OrganizationMember is one member of an organization.
type OrganizationMember struct {
	UserID    string  `json:"userId"`
	Email     *string `json:"email"`
	FirstName *string `json:"firstName"`
	LastName  *string `json:"lastName"`
	Role      string  `json:"role"`
	JoinedAt  string  `json:"joinedAt"`
}

// Membership is an organization a user belongs to, with their role.
type Membership struct {
	Organization Organization `json:"organization"`
	Role         string       `json:"role"`
	Permissions  []string     `json:"permissions"`
}

// OrganizationsService is Client.Organizations.
type OrganizationsService struct{ c *Client }

// ListForUser returns the organizations a user belongs to.
func (s *OrganizationsService) ListForUser(ctx context.Context, userID string) ([]Membership, error) {
	var out struct {
		Data []Membership `json:"data"`
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/organizations", url.Values{"userId": {userID}}, nil, &out)
	return out.Data, err
}

// OrganizationWithMembers is what Organizations.Get returns.
type OrganizationWithMembers struct {
	Organization Organization         `json:"organization"`
	Members      []OrganizationMember `json:"members"`
}

// Get returns an organization and its members.
func (s *OrganizationsService) Get(ctx context.Context, organizationID string) (*OrganizationWithMembers, error) {
	var out OrganizationWithMembers
	err := s.c.do(ctx, http.MethodGet, "/v1/organizations/"+escape(organizationID), nil, nil, &out)
	return &out, err
}

// CreateOrganizationParams are the fields for Organizations.Create.
type CreateOrganizationParams struct {
	Name       string `json:"name"`
	Slug       string `json:"slug,omitempty"`
	CreatedBy  string `json:"createdBy"`
	MaxMembers *int   `json:"maxMembers,omitempty"`
}

// Create creates an organization; CreatedBy becomes its first member.
func (s *OrganizationsService) Create(ctx context.Context, params CreateOrganizationParams) (*Organization, error) {
	var out struct {
		Organization Organization `json:"organization"`
	}
	err := s.c.do(ctx, http.MethodPost, "/v1/organizations", nil, params, &out)
	return &out.Organization, err
}

// Update changes the fields present in params, e.g. {"name": "Acme",
// "requireMfa": true}. A nil value clears the field.
func (s *OrganizationsService) Update(ctx context.Context, organizationID string, params map[string]any) (*Organization, error) {
	var out struct {
		Organization Organization `json:"organization"`
	}
	err := s.c.do(ctx, http.MethodPatch, "/v1/organizations/"+escape(organizationID), nil, params, &out)
	return &out.Organization, err
}

// Delete deletes an organization.
func (s *OrganizationsService) Delete(ctx context.Context, organizationID string) error {
	return s.c.do(ctx, http.MethodDelete, "/v1/organizations/"+escape(organizationID), nil, nil, nil)
}

// AddMemberParams are the fields for Organizations.AddMember.
type AddMemberParams struct {
	UserID string `json:"userId"`
	Role   string `json:"role,omitempty"`
}

// AddMember adds a user to an organization and returns their role.
func (s *OrganizationsService) AddMember(ctx context.Context, organizationID string, params AddMemberParams) (string, error) {
	var out struct {
		Role string `json:"role"`
	}
	err := s.c.do(ctx, http.MethodPost, "/v1/organizations/"+escape(organizationID)+"/members", nil, params, &out)
	return out.Role, err
}

// RemoveMember removes a user from an organization.
func (s *OrganizationsService) RemoveMember(ctx context.Context, organizationID, userID string) error {
	return s.c.do(ctx, http.MethodDelete, "/v1/organizations/"+escape(organizationID)+"/members/"+escape(userID), nil, nil, nil)
}
