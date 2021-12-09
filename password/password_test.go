/*
 * Copyright (c) 2021 Devtron Labs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Some of the code has been taken from argocd, for them argocd licensing terms apply
 */

package password

import (
	"testing"
)

func testPasswordHasher(t *testing.T, h PasswordHasher) {
	// Use the default work factor
	const (
		defaultPassword = "Hello, world!"
		pollution       = "extradata12345"
	)
	hashedPassword, _ := h.HashPassword(defaultPassword)
	if !h.VerifyPassword(defaultPassword, hashedPassword) {
		t.Errorf("Password %q should have validated against hash %q", defaultPassword, hashedPassword)
	}
	if h.VerifyPassword(defaultPassword, pollution+hashedPassword) {
		t.Errorf("Password %q should NOT have validated against hash %q", defaultPassword, pollution+hashedPassword)
	}
}

func TestBcryptPasswordHasher(t *testing.T) {
	// Use the default work factor
	h := BcryptPasswordHasher{0}
	testPasswordHasher(t, h)
}

func TestDummyPasswordHasher(t *testing.T) {
	h := DummyPasswordHasher{}
	testPasswordHasher(t, h)
}

func TestPasswordHashing(t *testing.T) {
	const (
		defaultPassword = "Hello, world!"
		blankPassword   = ""
	)
	hashers := []PasswordHasher{
		BcryptPasswordHasher{0},
		DummyPasswordHasher{},
	}

	hashedPassword, _ := hashPasswordWithHashers(defaultPassword, hashers)
	valid, stale := verifyPasswordWithHashers(defaultPassword, hashedPassword, hashers)
	if !valid {
		t.Errorf("Password %q should have validated against hash %q", defaultPassword, hashedPassword)
	}
	if stale {
		t.Errorf("Password %q should not have been marked stale against hash %q", defaultPassword, hashedPassword)
	}
	valid, stale = verifyPasswordWithHashers(defaultPassword, defaultPassword, hashers)
	if !valid {
		t.Errorf("Password %q should have validated against itself with dummy hasher", defaultPassword)
	}
	if !stale {
		t.Errorf("Password %q should have been acknowledged stale against itself with dummy hasher", defaultPassword)
	}

	hashedPassword, err := hashPasswordWithHashers(blankPassword, hashers)
	if err == nil {
		t.Errorf("Blank password should have produced error, rather than hash %q", hashedPassword)
	}

	valid, _ = verifyPasswordWithHashers(blankPassword, "", hashers)
	if valid != false {
		t.Errorf("Blank password should have failed verification")
	}
}
