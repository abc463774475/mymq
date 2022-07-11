// Copyright 2012-2019 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/internal/ldap"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/bcrypt"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
)

// NkeyUser is for multiple nkey based users
type NkeyUser struct {
	Nkey                   string              `json:"user"`
	Account                *Account            `json:"account,omitempty"`
	SigningKey             string              `json:"signing_key,omitempty"`
	AllowedConnectionTypes map[string]struct{} `json:"connection_types,omitempty"`
}

// User is for multiple accounts/users.
type User struct {
	Username               string              `json:"user"`
	Password               string              `json:"password"`
	Account                *Account            `json:"account,omitempty"`
	AllowedConnectionTypes map[string]struct{} `json:"connection_types,omitempty"`
}

// clone performs a deep copy of the User struct, returning a new clone with
// all values copied.
func (u *User) clone() *User {
	if u == nil {
		return nil
	}
	clone := &User{}
	*clone = *u
	return clone
}

// clone performs a deep copy of the NkeyUser struct, returning a new clone with
// all values copied.
func (n *NkeyUser) clone() *NkeyUser {
	if n == nil {
		return nil
	}
	clone := &NkeyUser{}
	*clone = *n
	return clone
}

// checkAuthforWarnings will look for insecure settings and log concerns.
// Lock is assumed held.
func (s *Server) checkAuthforWarnings() {
	warn := false
	if s.opts.Password != _EMPTY_ && !isBcrypt(s.opts.Password) {
		warn = true
	}
	for _, u := range s.users {
		// Skip warn if using TLS certs based auth
		// unless a password has been left in the config.
		if u.Password == _EMPTY_ && s.opts.TLSMap {
			continue
		}
		// Check if this is our internal sys client created on the fly.
		if s.sysAccOnlyNoAuthUser != _EMPTY_ && u.Username == s.sysAccOnlyNoAuthUser {
			continue
		}
		if !isBcrypt(u.Password) {
			warn = true
			break
		}
	}
	if warn {
		// Warning about using plaintext passwords.
		s.Warnf("Plaintext passwords detected, use nkeys or bcrypt")
	}
}

// If Users or Nkeys options have definitions without an account defined,
// assign them to the default global account.
// Lock should be held.
func (s *Server) assignGlobalAccountToOrphanUsers(nkeys map[string]*NkeyUser, users map[string]*User) {
	for _, u := range users {
		if u.Account == nil {
			u.Account = s.gacc
		}
	}
	for _, u := range nkeys {
		if u.Account == nil {
			u.Account = s.gacc
		}
	}
}

// Takes the given slices of NkeyUser and User options and build
// corresponding maps used by the server. The users are cloned
// so that server does not reference options.
// The global account is assigned to users that don't have an
// existing account.
// Server lock is held on entry.
func (s *Server) buildNkeysAndUsersFromOptions(nko []*NkeyUser, uo []*User) (map[string]*NkeyUser, map[string]*User) {
	var nkeys map[string]*NkeyUser
	var users map[string]*User

	if nko != nil {
		nkeys = make(map[string]*NkeyUser, len(nko))
		for _, u := range nko {
			copy := u.clone()
			if u.Account != nil {
				if v, ok := s.accounts.Load(u.Account.Name); ok {
					copy.Account = v.(*Account)
				}
			}
			nkeys[u.Nkey] = copy
		}
	}
	if uo != nil {
		users = make(map[string]*User, len(uo))
		for _, u := range uo {
			copy := u.clone()
			if u.Account != nil {
				if v, ok := s.accounts.Load(u.Account.Name); ok {
					copy.Account = v.(*Account)
				}
			}
			users[u.Username] = copy
		}
	}
	s.assignGlobalAccountToOrphanUsers(nkeys, users)
	return nkeys, users
}

// returns false if the client needs to be disconnected
func (c *client) matchesPinnedCert(tlsPinnedCerts PinnedCertSet) bool {
	if tlsPinnedCerts == nil {
		return true
	}
	tlsState := c.GetTLSConnectionState()
	if tlsState == nil || len(tlsState.PeerCertificates) == 0 || tlsState.PeerCertificates[0] == nil {
		c.Debugf("Failed pinned cert test as client did not provide a certificate")
		return false
	}
	sha := sha256.Sum256(tlsState.PeerCertificates[0].RawSubjectPublicKeyInfo)
	keyId := hex.EncodeToString(sha[:])
	if _, ok := tlsPinnedCerts[keyId]; !ok {
		c.Debugf("Failed pinned cert test for key id: %s", keyId)
		return false
	}
	return true
}

func (s *Server) processClientOrLeafAuthentication(c *client, opts *Options) bool {
	var (
		nkey *NkeyUser
		juc  *jwt.UserClaims
		acc  *Account
		user *User
		ok   bool
		err  error
		ao   bool // auth override
	)
	s.mu.Lock()
	authRequired := s.info.AuthRequired
	if !authRequired {
		// If no auth required for regular clients, then check if
		switch c.clientType() {
		}
	}
	if !authRequired {
		// TODO(dlc) - If they send us credentials should we fail?
		s.mu.Unlock()
		return true
	}
	var (
		username      string
		password      string
		token         string
		noAuthUser    string
		pinnedAcounts map[string]struct{}
	)
	tlsMap := opts.TLSMap
	if c.kind == CLIENT {
		switch c.clientType() {

		}
	} else {
	}

	if !ao {
		noAuthUser = opts.NoAuthUser
		username = opts.Username
		password = opts.Password
		token = opts.Authorization
	}

	// Check if we have trustedKeys defined in the server. If so we require a user jwt.
	if s.trustedKeys != nil {
		if c.opts.JWT == _EMPTY_ {
			s.mu.Unlock()
			c.Debugf("Authentication requires a user JWT")
			return false
		}
		// So we have a valid user jwt here.
		juc, err = jwt.DecodeUserClaims(c.opts.JWT)
		if err != nil {
			s.mu.Unlock()
			c.Debugf("User JWT not valid: %v", err)
			return false
		}
		vr := jwt.CreateValidationResults()
		juc.Validate(vr)
		if vr.IsBlocking(true) {
			s.mu.Unlock()
			c.Debugf("User JWT no longer valid: %+v", vr)
			return false
		}
		pinnedAcounts = opts.resolverPinnedAccounts
	}

	// Check if we have nkeys or users for client.
	hasNkeys := len(s.nkeys) > 0
	hasUsers := len(s.users) > 0
	if hasNkeys && c.opts.Nkey != _EMPTY_ {
		nkey, ok = s.nkeys[c.opts.Nkey]
		if !ok || !c.connectionTypeAllowed(nkey.AllowedConnectionTypes) {
			s.mu.Unlock()
			return false
		}
	} else if hasUsers {
		// Check if we are tls verify and are mapping users from the client_certificate.
		if tlsMap {
			authorized := checkClientTLSCertSubject(c, func(u string, certDN *ldap.DN, _ bool) (string, bool) {
				// First do literal lookup using the resulting string representation
				// of RDNSequence as implemented by the pkix package from Go.
				if u != _EMPTY_ {
					usr, ok := s.users[u]
					if !ok || !c.connectionTypeAllowed(usr.AllowedConnectionTypes) {
						return _EMPTY_, false
					}
					user = usr
					return usr.Username, true
				}

				if certDN == nil {
					return _EMPTY_, false
				}

				// Look through the accounts for a DN that is equal to the one
				// presented by the certificate.
				dns := make(map[*User]*ldap.DN)
				for _, usr := range s.users {
					if !c.connectionTypeAllowed(usr.AllowedConnectionTypes) {
						continue
					}
					// TODO: Use this utility to make a full validation pass
					// on start in case tlsmap feature is being used.
					inputDN, err := ldap.ParseDN(usr.Username)
					if err != nil {
						continue
					}
					if inputDN.Equal(certDN) {
						user = usr
						return usr.Username, true
					}

					// In case it did not match exactly, then collect the DNs
					// and try to match later in case the DN was reordered.
					dns[usr] = inputDN
				}

				// Check in case the DN was reordered.
				for usr, inputDN := range dns {
					if inputDN.RDNsMatch(certDN) {
						user = usr
						return usr.Username, true
					}
				}
				return _EMPTY_, false
			})
			if !authorized {
				s.mu.Unlock()
				return false
			}
			if c.opts.Username != _EMPTY_ {
				s.Warnf("User %q found in connect proto, but user required from cert", c.opts.Username)
			}
			// Already checked that the client didn't send a user in connect
			// but we set it here to be able to identify it in the logs.
			c.opts.Username = user.Username
		} else {
			if (c.kind == CLIENT) && noAuthUser != _EMPTY_ &&
				c.opts.Username == _EMPTY_ && c.opts.Password == _EMPTY_ && c.opts.Token == _EMPTY_ {
				if u, exists := s.users[noAuthUser]; exists {
					c.mu.Lock()
					c.opts.Username = u.Username
					c.opts.Password = u.Password
					c.mu.Unlock()
				}
			}
			if c.opts.Username != _EMPTY_ {
				user, ok = s.users[c.opts.Username]
				if !ok || !c.connectionTypeAllowed(user.AllowedConnectionTypes) {
					s.mu.Unlock()
					return false
				}
			}
		}
	}
	s.mu.Unlock()

	// If we have a jwt and a userClaim, make sure we have the Account, etc associated.
	// We need to look up the account. This will use an account resolver if one is present.
	if juc != nil {
		allowedConnTypes, err := convertAllowedConnectionTypes(juc.AllowedConnectionTypes)
		if err != nil {
			// We got an error, which means some connection types were unknown. As long as
			// a valid one is returned, we proceed with auth. If not, we have to reject.
			// . No error
			//
			// Client will be rejected if not a  or proceed with rest of
			// auth if it is.
			// Now suppose JWT allows
			// server. In this case, allowedConnTypes would contain  and we
			// However, say that the JWT only (and again suppose this server
			// map would be empty (no valid types found), and since empty means allow-all,
			// then we should reject because the intent was to allow connections for this

			c.Debugf("%v", err)
			if len(allowedConnTypes) == 0 {
				return false
			}
			err = nil
		}
		if !c.connectionTypeAllowed(allowedConnTypes) {
			c.Debugf("Connection type not allowed")
			return false
		}
		issuer := juc.Issuer
		if juc.IssuerAccount != _EMPTY_ {
			issuer = juc.IssuerAccount
		}
		if pinnedAcounts != nil {
			if _, ok := pinnedAcounts[issuer]; !ok {
				c.Debugf("Account %s not listed as operator pinned account", issuer)
				atomic.AddUint64(&s.pinnedAccFail, 1)
				return false
			}
		}
		if acc, err = s.LookupAccount(issuer); acc == nil {
			c.Debugf("Account JWT lookup error: %v", err)
			return false
		}
		if !s.isTrustedIssuer(acc.Issuer) {
			c.Debugf("Account JWT not signed by trusted operator")
			return false
		}
		if scope, ok := acc.hasIssuer(juc.Issuer); !ok {
			c.Debugf("User JWT issuer is not known")
			return false
		} else if scope != nil {
			if err := scope.ValidateScopedSigner(juc); err != nil {
				c.Debugf("User JWT is not valid: %v", err)
				return false
			} else if uSc, ok := scope.(*jwt.UserScope); !ok {
				c.Debugf("User JWT is not valid")
				return false
			} else {
				juc.UserPermissionLimits = uSc.Template
			}
		}
		if acc.IsExpired() {
			c.Debugf("Account JWT has expired")
			return false
		}
		if juc.BearerToken && acc.failBearer() {
			c.Debugf("Account does not allow bearer token")
			return false
		}
		// skip validation of nonce when presented with a bearer token
		// FIXME: if BearerToken is only for WSS, need check for server with that port enabled
		if !juc.BearerToken {
			// Verify the signature against the nonce.
			if c.opts.Sig == _EMPTY_ {
				c.Debugf("Signature missing")
				return false
			}
			sig, err := base64.RawURLEncoding.DecodeString(c.opts.Sig)
			if err != nil {
				// Allow fallback to normal base64.
				sig, err = base64.StdEncoding.DecodeString(c.opts.Sig)
				if err != nil {
					c.Debugf("Signature not valid base64")
					return false
				}
			}
			pub, err := nkeys.FromPublicKey(juc.Subject)
			if err != nil {
				c.Debugf("User nkey not valid: %v", err)
				return false
			}
			if err := pub.Verify(c.nonce, sig); err != nil {
				c.Debugf("Signature not verified")
				return false
			}
		}
		if acc.checkUserRevoked(juc.Subject, juc.IssuedAt) {
			c.Debugf("User authentication revoked")
			return false
		}

		nkey = buildInternalNkeyUser(juc, allowedConnTypes, acc)
		if err := c.RegisterNkeyUser(nkey); err != nil {
			return false
		}

		// Hold onto the user's public key.
		c.mu.Lock()
		c.pubKey = juc.Subject
		c.tags = juc.Tags
		c.nameTag = juc.Name
		c.mu.Unlock()

		acc.mu.RLock()
		c.Debugf("Authenticated JWT: %s %q (claim-name: %q, claim-tags: %q) "+
			"signed with %q by Account %q (claim-name: %q, claim-tags: %q) signed with %q has mappings %t accused %p",
			c.kindString(), juc.Subject, juc.Name, juc.Tags, juc.Issuer, issuer, acc.nameTag, acc.tags, acc.Issuer, acc.hasMappingsLocked(), acc)
		acc.mu.RUnlock()
		return true
	}

	if nkey != nil {
		if c.opts.Sig == _EMPTY_ {
			c.Debugf("Signature missing")
			return false
		}
		sig, err := base64.RawURLEncoding.DecodeString(c.opts.Sig)
		if err != nil {
			// Allow fallback to normal base64.
			sig, err = base64.StdEncoding.DecodeString(c.opts.Sig)
			if err != nil {
				c.Debugf("Signature not valid base64")
				return false
			}
		}
		pub, err := nkeys.FromPublicKey(c.opts.Nkey)
		if err != nil {
			c.Debugf("User nkey not valid: %v", err)
			return false
		}
		if err := pub.Verify(c.nonce, sig); err != nil {
			c.Debugf("Signature not verified")
			return false
		}
		if err := c.RegisterNkeyUser(nkey); err != nil {
			return false
		}
		return true
	}
	if user != nil {
		ok = comparePasswords(user.Password, c.opts.Password)
		// If we are authorized, register the user which will properly setup any permissions
		// for pub/sub authorizations.
		if ok {
			c.RegisterUser(user)
		}
		return ok
	}

	if c.kind == CLIENT {
		if token != _EMPTY_ {
			return comparePasswords(token, c.opts.Token)
		} else if username != _EMPTY_ {
			if username != c.opts.Username {
				return false
			}
			return comparePasswords(password, c.opts.Password)
		}
	}
	return false
}

func getTLSAuthDCs(rdns *pkix.RDNSequence) string {
	dcOID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	dcs := []string{}
	for _, rdn := range *rdns {
		if len(rdn) == 0 {
			continue
		}
		for _, atv := range rdn {
			value, ok := atv.Value.(string)
			if !ok {
				continue
			}
			if atv.Type.Equal(dcOID) {
				dcs = append(dcs, "DC="+value)
			}
		}
	}
	return strings.Join(dcs, ",")
}

type tlsMapAuthFn func(string, *ldap.DN, bool) (string, bool)

func checkClientTLSCertSubject(c *client, fn tlsMapAuthFn) bool {
	tlsState := c.GetTLSConnectionState()
	if tlsState == nil {
		c.Debugf("User required in cert, no TLS connection state")
		return false
	}
	if len(tlsState.PeerCertificates) == 0 {
		c.Debugf("User required in cert, no peer certificates found")
		return false
	}
	cert := tlsState.PeerCertificates[0]
	if len(tlsState.PeerCertificates) > 1 {
		c.Debugf("Multiple peer certificates found, selecting first")
	}

	hasSANs := len(cert.DNSNames) > 0
	hasEmailAddresses := len(cert.EmailAddresses) > 0
	hasSubject := len(cert.Subject.String()) > 0
	hasURIs := len(cert.URIs) > 0
	if !hasEmailAddresses && !hasSubject && !hasURIs {
		c.Debugf("User required in cert, none found")
		return false
	}

	switch {
	case hasEmailAddresses:
		for _, u := range cert.EmailAddresses {
			if match, ok := fn(u, nil, false); ok {
				c.Debugf("Using email found in cert for auth [%q]", match)
				return true
			}
		}
		fallthrough
	case hasSANs:
		for _, u := range cert.DNSNames {
			if match, ok := fn(u, nil, true); ok {
				c.Debugf("Using SAN found in cert for auth [%q]", match)
				return true
			}
		}
		fallthrough
	case hasURIs:
		for _, u := range cert.URIs {
			if match, ok := fn(u.String(), nil, false); ok {
				c.Debugf("Using URI found in cert for auth [%q]", match)
				return true
			}
		}
	}

	// Use the string representation of the full RDN Sequence including
	// the domain components in case there are any.
	rdn := cert.Subject.ToRDNSequence().String()

	// Match using the raw subject to avoid ignoring attributes.
	// https://github.com/golang/go/issues/12342
	dn, err := ldap.FromRawCertSubject(cert.RawSubject)
	if err == nil {
		if match, ok := fn("", dn, false); ok {
			c.Debugf("Using DistinguishedNameMatch for auth [%q]", match)
			return true
		}
		c.Debugf("DistinguishedNameMatch could not be used for auth [%q]", rdn)
	}

	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(cert.RawSubject, &rdns); err == nil {
		// If found domain components then include roughly following
		// the order from https://tools.ietf.org/html/rfc2253
		//
		// NOTE: The original sequence from string representation by ToRDNSequence does not follow
		// the correct ordering, so this addition ofdomainComponents would likely be deprecated in
		// another release in favor of using the correct ordered as parsed by the go-ldap library.
		//
		dcs := getTLSAuthDCs(&rdns)
		if len(dcs) > 0 {
			u := strings.Join([]string{rdn, dcs}, ",")
			if match, ok := fn(u, nil, false); ok {
				c.Debugf("Using RDNSequence for auth [%q]", match)
				return true
			}
			c.Debugf("RDNSequence could not be used for auth [%q]", u)
		}
	}

	// If no match, then use the string representation of the RDNSequence
	// from the subject without the domainComponents.
	if match, ok := fn(rdn, nil, false); ok {
		c.Debugf("Using certificate subject for auth [%q]", match)
		return true
	}

	c.Debugf("User in cert [%q], not found", rdn)
	return false
}

func dnsAltNameLabels(dnsAltName string) []string {
	return strings.Split(strings.ToLower(dnsAltName), ".")
}

// Check DNS name according to https://tools.ietf.org/html/rfc6125#section-6.4.1
func dnsAltNameMatches(dnsAltNameLabels []string, urls []*url.URL) bool {
URLS:
	for _, url := range urls {
		if url == nil {
			continue URLS
		}
		hostLabels := strings.Split(strings.ToLower(url.Hostname()), ".")
		// Following https://tools.ietf.org/html/rfc6125#section-6.4.3, should not => will not, may => will not
		// The wilcard * never matches multiple label and only matches the left most label.
		if len(hostLabels) != len(dnsAltNameLabels) {
			continue URLS
		}
		i := 0
		// only match wildcard on left most label
		if dnsAltNameLabels[0] == "*" {
			i++
		}
		for ; i < len(dnsAltNameLabels); i++ {
			if dnsAltNameLabels[i] != hostLabels[i] {
				continue URLS
			}
		}
		return true
	}
	return false
}

func (s *Server) registerLeafWithAccount(c *client, account string) bool {
	var err error
	acc := s.globalAccount()
	if account != _EMPTY_ {
		acc, err = s.lookupAccount(account)
		if err != nil {
			s.Errorf("authentication of user %q failed, unable to lookup account %q: %v",
				c.opts.Username, account, err)
			return false
		}
	}
	if err = c.registerWithAccount(acc); err != nil {
		return false
	}
	return true
}

// Support for bcrypt stored passwords and tokens.
var validBcryptPrefix = regexp.MustCompile(`^\$2[abxy]\$\d{2}\$.*`)

// isBcrypt checks whether the given password or token is bcrypted.
func isBcrypt(password string) bool {
	if strings.HasPrefix(password, "$") {
		return validBcryptPrefix.MatchString(password)
	}

	return false
}

func comparePasswords(serverPassword, clientPassword string) bool {
	// Check to see if the server password is a bcrypt hash
	if isBcrypt(serverPassword) {
		if err := bcrypt.CompareHashAndPassword([]byte(serverPassword), []byte(clientPassword)); err != nil {
			return false
		}
	} else if serverPassword != clientPassword {
		return false
	}
	return true
}
