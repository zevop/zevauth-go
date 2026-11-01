package zevauth

// Claims are a verified token's contents (contract §1.1). Absent claims
// are absent: optional strings are empty, optional lists are nil.
type Claims struct {
	Issuer    string
	Audience  []string
	Subject   string // the user's public id
	SessionID string
	IssuedAt  int64
	NotBefore int64
	ExpiresAt int64
	ID        string // jti

	Email          string
	EmailVerified  bool
	Name           string
	Picture        string
	PublicMetadata map[string]any

	OrgID          string
	OrgSlug        string
	OrgName        string
	OrgRole        string
	OrgPermissions []string

	PendingTasks []string
	AMR          []string

	// Raw holds every claim as decoded, including ones this version does
	// not know about.
	Raw map[string]any
}

func (c *Claims) audienceIs(environmentID string) bool {
	for _, a := range c.Audience {
		if a == environmentID {
			return true
		}
	}
	return false
}

// claimsFrom reads the known claims. A known claim of the wrong type is
// malformed_token; unknown claims are kept in Raw and otherwise ignored.
func claimsFrom(raw map[string]any) (*Claims, error) {
	c := &Claims{Raw: raw}
	var bad string

	str := func(name string, required bool) string {
		v, ok := raw[name]
		if !ok {
			if required && bad == "" {
				bad = name
			}
			return ""
		}
		s, ok := v.(string)
		if !ok && bad == "" {
			bad = name
		}
		return s
	}
	num := func(name string) int64 {
		v, ok := raw[name]
		if !ok {
			return 0
		}
		f, ok := v.(float64)
		if !ok && bad == "" {
			bad = name
		}
		return int64(f)
	}
	list := func(name string) []string {
		v, ok := raw[name]
		if !ok {
			return nil
		}
		items, ok := v.([]any)
		if !ok {
			if bad == "" {
				bad = name
			}
			return nil
		}
		out := make([]string, 0, len(items))
		for _, item := range items {
			s, ok := item.(string)
			if !ok {
				if bad == "" {
					bad = name
				}
				return nil
			}
			out = append(out, s)
		}
		return out
	}

	c.Issuer = str("iss", true)
	c.Subject = str("sub", true)
	c.SessionID = str("sid", false)
	c.ID = str("jti", false)
	c.IssuedAt = num("iat")
	c.NotBefore = num("nbf")
	c.ExpiresAt = num("exp")
	c.Email = str("email", false)
	c.Name = str("name", false)
	c.Picture = str("picture", false)
	c.OrgID = str("org_id", false)
	c.OrgSlug = str("org_slug", false)
	c.OrgName = str("org_name", false)
	c.OrgRole = str("org_role", false)
	c.OrgPermissions = list("org_permissions")
	c.PendingTasks = list("pending_tasks")
	c.AMR = list("amr")

	switch aud := raw["aud"].(type) {
	case string:
		c.Audience = []string{aud}
	case []any:
		c.Audience = list("aud")
	case nil:
	default:
		if bad == "" {
			bad = "aud"
		}
	}
	if v, ok := raw["email_verified"]; ok {
		b, isBool := v.(bool)
		if !isBool && bad == "" {
			bad = "email_verified"
		}
		c.EmailVerified = b
	}
	if v, ok := raw["public_metadata"]; ok {
		m, isMap := v.(map[string]any)
		if !isMap && v != nil && bad == "" {
			bad = "public_metadata"
		}
		c.PublicMetadata = m
	}

	if bad != "" {
		return nil, verifyErr(CodeMalformedToken, "claim "+bad+" has the wrong type")
	}
	return c, nil
}
