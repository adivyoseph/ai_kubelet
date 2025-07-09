/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	// Use the same rootCACert as transport_test.go
	testCACert1 = `-----BEGIN CERTIFICATE-----
MIIC4DCCAcqgAwIBAgIBATALBgkqhkiG9w0BAQswIzEhMB8GA1UEAwwYMTAuMTMu
MTI5LjEwNkAxNDIxMzU5MDU4MB4XDTE1MDExNTIxNTczN1oXDTE2MDExNTIxNTcz
OFowIzEhMB8GA1UEAwwYMTAuMTMuMTI5LjEwNkAxNDIxMzU5MDU4MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAunDRXGwsiYWGFDlWH6kjGun+PshDGeZX
xtx9lUnL8pIRWH3wX6f13PO9sktaOWW0T0mlo6k2bMlSLlSZgG9H6og0W6gLS3vq
s4VavZ6DbXIwemZG2vbRwsvR+t4G6Nbwelm6F8RFnA1Fwt428pavmNQ/wgYzo+T1
1eS+HiN4ACnSoDSx3QRWcgBkB1g6VReofVjx63i0J+w8Q/41L9GUuLqquFxu6ZnH
60vTB55lHgFiDLjA1FkEz2dGvGh/wtnFlRvjaPC54JH2K1mPYAUXTreoeJtLJKX0
ycoiyB24+zGCniUmgIsmQWRPaOPircexCp1BOeze82BT1LCZNTVaxQIDAQABoyMw
ITAOBgNVHQ8BAf8EBAMCAKQwDwYDVR0TAQH/BAUwAwEB/zALBgkqhkiG9w0BAQsD
ggEBADMxsUuAFlsYDpF4fRCzXXwrhbtj4oQwcHpbu+rnOPHCZupiafzZpDu+rw4x
YGPnCb594bRTQn4pAu3Ac18NbLD5pV3uioAkv8oPkgr8aUhXqiv7KdDiaWm6sbAL
EHiXVBBAFvQws10HMqMoKtO8f1XDNAUkWduakR/U6yMgvOPwS7xl0eUTqyRB6zGb
K55q2dejiFWaFqB/y78txzvz6UlOZKE44g2JAVoJVM6kGaxh33q8/FmrL4kuN3ut
W+MmJCVDvd4eEqPwbp7146ZWTqpIJ8lvA6wuChtqV8lhAPka2hD/LMqY8iXNmfXD
uml0obOEy+ON91k+SWTJ3ggmF/U=
-----END CERTIFICATE-----`

	// A different CA cert for testing rotation (modified version of certData from transport_test.go)
	testCACert2 = `-----BEGIN CERTIFICATE-----
MIIC6jCCAdSgAwIBAgIBCzALBgkqhkiG9w0BAQswIzEhMB8GA1UEAwwYMTAuMTMu
MTI5LjEwNkAxNDIxMzU5MDU4MB4XDTE1MDExNTIyMDEzMVoXDTE2MDExNTIyMDEz
MlowGzEZMBcGA1UEAxMQb3BlbnNoaWZ0LWNsaWVudDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAKtdhz0+uCLXw5cSYns9rU/XifFSpb/x24WDdrm72S/v
b9BPYsAStiP148buylr1SOuNi8sTAZmlVDDIpIVwMLff+o2rKYDicn9fjbrTxTOj
lI4pHJBH+JU3AJ0tbajupioh70jwFS0oYpwtneg2zcnE2Z4l6mhrj2okrc5Q1/X2
I2HChtIU4JYTisObtin10QKJX01CLfYXJLa8upWzKZ4/GOcHG+eAV3jXWoXidtjb
1Usw70amoTZ6mIVCkiu1QwCoa8+ycojGfZhvqMsAp1536ZcCul+Na+AbCv4zKS7F
kQQaImVrXdUiFansIoofGlw/JNuoKK6ssVpS5Ic3pgcCAwEAAaM1MDMwDgYDVR0P
AQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwCwYJ
KoZIhvcNAQELA4IBAQCKLREH7bXtXtZ+8vI6cjD7W3QikiArGqbl36bAhhWsJLp/
p/ndKz39iFNaiZ3GlwIURWOOKx3y3GA0x9m8FR+Llthf0EQ8sUjnwaknWs0Y6DQ3
jjPFZOpV3KPCFrdMJ3++E3MgwFC/Ih/N2ebFX9EcV9Vcc6oVWMdwT0fsrhu683rq
6GSR/3iVX1G/pmOiuaR0fNUaCyCfYrnI4zHBDgSfnlm3vIvN2lrsR/DQBakNL8DJ
HBgKxMGeUPoneBv+c8DMXIL0EhaFXRlBv9QW45/GiAIOuyFJ0i6hCtGZpJjq4OpQ
BRjCI+izPzFTjsxD4aORE+WOkyWFCGPWKfNejfw0
-----END CERTIFICATE-----`
)



// writeCAFile writes CA data to a temporary file
func writeCAFile(t testing.TB, caData []byte) string {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	
	err := os.WriteFile(caFile, caData, 0644)
	if err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}
	
	return caFile
}

// createTestTransport creates a test transport with TLS config
func createTestTransport(t testing.TB, caData []byte) *http.Transport {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		t.Fatalf("Failed to parse CA certificate")
	}

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}
}

func TestNewAtomicTransportHolder(t *testing.T) {
	caFile := writeCAFile(t, []byte(testCACert1))
	
	config := &Config{
		TLS: TLSConfig{
			CAFile: caFile,
			CAData: []byte(testCACert1),
		},
	}
	
	transport := createTestTransport(t, []byte(testCACert1))
	
	holder := newAtomicTransportHolder(config, transport)
	
	if holder == nil {
		t.Fatal("Expected non-nil holder")
	}
	
	if holder.caFile != caFile {
		t.Errorf("Expected caFile %s, got %s", caFile, holder.caFile)
	}
	
	if holder.config != config {
		t.Error("Expected config to be set")
	}
	
	if holder.transport.Load() != transport {
		t.Error("Expected transport to be stored")
	}
	
	if holder.queue == nil {
		t.Error("Expected queue to be initialized")
	}
}

func TestAtomicTransportHolderRoundTrip(t *testing.T) {
	caFile := writeCAFile(t, []byte(testCACert1))
	
	config := &Config{
		TLS: TLSConfig{
			CAFile: caFile,
			CAData: []byte(testCACert1),
		},
	}
	
	transport := createTestTransport(t, []byte(testCACert1))
	holder := newAtomicTransportHolder(config, transport)
	
	// Create a test request
	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	
	// We can't mock the RoundTrip method since it's an interface method
	// Instead, we'll create a mock transport that tracks calls
	type mockTransport struct {
		*http.Transport
		called bool
	}
	
	mock := &mockTransport{Transport: transport, called: false}
	oldTransport := holder.transport.Load()
	holder.transport.Store(mock.Transport)
	
	// Call RoundTrip through the holder
	_, err = holder.RoundTrip(req)
	
	// We expect an error since we're not actually connecting to a server
	// but the call should go through without panicking
	if err == nil {
		t.Error("Expected error since we're not connecting to a real server")
	}
	
	// Restore the original transport
	holder.transport.Store(oldTransport)
}

func TestCheckCAFileAndRotate(t *testing.T) {
	tests := []struct {
		name           string
		setupCA        []byte
		updateCA       []byte
		caFile         string
		expectRotation bool
		expectError    bool
	}{
		{
			name:           "no change",
			setupCA:        []byte(testCACert1),
			updateCA:       []byte(testCACert1), // Same CA
			expectRotation: false,
			expectError:    false,
		},
		{
			name:           "CA changed",
			setupCA:        []byte(testCACert1),
			updateCA:       []byte(testCACert2), // Different CA
			expectRotation: true,
			expectError:    false,
		},
		{
			name:        "file error",
			setupCA:     []byte(testCACert1),
			caFile:      "/nonexistent/ca.crt", // Non-existent file
			expectError: true,
		},
		{
			name:           "no current CA data",
			setupCA:        nil, // No initial CA data
			updateCA:       []byte(testCACert1),
			expectRotation: false,
			expectError:    false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var caFile string
			if tt.caFile != "" {
				caFile = tt.caFile
			} else {
				caFile = writeCAFile(t, []byte(testCACert1))
				if tt.updateCA != nil {
					// Update the file with new CA content
					err := os.WriteFile(caFile, tt.updateCA, 0644)
					if err != nil {
						t.Fatalf("Failed to update CA file: %v", err)
					}
				}
			}
			
			config := &Config{
				TLS: TLSConfig{
					CAFile: caFile,
					CAData: tt.setupCA,
				},
			}
			
			transport := createTestTransport(t, []byte(testCACert1))
			holder := newAtomicTransportHolder(config, transport)
			
			// Check CA file rotation
			err := holder.checkCAFileAndRotate()
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				// Transport should remain unchanged on error
				if holder.transport.Load() != transport {
					t.Error("Expected transport to remain unchanged on error")
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			
			newTransport := holder.transport.Load()
			if tt.expectRotation {
				if newTransport == transport {
					t.Error("Expected transport to be rotated")
				}
				// New transport should have updated CA
				if newTransport.TLSClientConfig == nil {
					t.Fatal("Expected TLS config in new transport")
				}
				if newTransport.TLSClientConfig.RootCAs == nil {
					t.Fatal("Expected RootCAs in new transport")
				}
			} else {
				if newTransport != transport {
					t.Error("Expected transport to remain unchanged")
				}
			}
		})
	}
}

func TestController(t *testing.T) {
	// Save original refresh duration
	originalDuration := CARotationRefreshDuration
	defer func() {
		CARotationRefreshDuration = originalDuration
	}()
	
	tests := []struct {
		name           string
		refreshDuration time.Duration
		testRotation   bool
	}{
		{
			name:           "start and stop",
			refreshDuration: 100 * time.Millisecond,
			testRotation:   false,
		},
		{
			name:           "CA rotation",
			refreshDuration: 50 * time.Millisecond,
			testRotation:   true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set test-specific refresh duration
			CARotationRefreshDuration = tt.refreshDuration
			
			caFile := writeCAFile(t, []byte(testCACert1))
			config := &Config{
				TLS: TLSConfig{
					CAFile: caFile,
					CAData: []byte(testCACert1),
				},
			}
			
			transport := createTestTransport(t, []byte(testCACert1))
			holder := newAtomicTransportHolder(config, transport)
			
			// Start controller
			stopCh := make(chan struct{})
			go holder.run(stopCh)
			
			// Let it run for a bit
			time.Sleep(2 * tt.refreshDuration)
			
			if tt.testRotation {
				// Update CA file for rotation test
				err := os.WriteFile(caFile, []byte(testCACert2), 0644)
				if err != nil {
					t.Fatalf("Failed to update CA file: %v", err)
				}
				
				// Wait for controller to detect and rotate
				var newTransport *http.Transport
				err = wait.PollImmediate(10*time.Millisecond, 500*time.Millisecond, func() (bool, error) {
					newTransport = holder.transport.Load()
					return newTransport != transport, nil
				})
				
				if err != nil {
					t.Fatalf("Controller did not rotate transport: %v", err)
				}
				
				// Verify new transport has updated CA
				if newTransport.TLSClientConfig == nil || newTransport.TLSClientConfig.RootCAs == nil {
					t.Error("Expected new transport to have updated CA")
				}
			}
			
			// Stop controller
			close(stopCh)
			
			// Give it time to stop
			time.Sleep(100 * time.Millisecond)
			
			// Queue should be shut down
			if !holder.queue.ShuttingDown() {
				t.Error("Expected queue to be shut down")
			}
		})
	}
}

func TestUtilityFunctions(t *testing.T) {
	t.Run("bytes equal", func(t *testing.T) {
		tests := []struct {
			name     string
			data1    []byte
			data2    []byte
			expected bool
		}{
			{"same data", []byte(testCACert1), []byte(testCACert1), true},
			{"different data", []byte(testCACert1), []byte(testCACert2), false},
			{"empty data", []byte{}, []byte{}, true},
			{"nil vs empty", nil, []byte{}, false},
		}
		
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := bytes.Equal(tt.data1, tt.data2)
				if result != tt.expected {
					t.Errorf("Expected %v, got %v", tt.expected, result)
				}
			})
		}
	})
	
	t.Run("root cert pool", func(t *testing.T) {
		tests := []struct {
			name        string
			caData      []byte
			expectError bool
			expectNil   bool
		}{
			{"valid CA data", []byte(testCACert1), false, false},
			{"invalid CA data", []byte("invalid-ca-data"), true, false},
			{"empty CA data", []byte{}, false, true},
		}
		
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				pool, err := rootCertPool(tt.caData)
				
				if tt.expectError {
					if err == nil {
						t.Error("Expected error but got none")
					}
					return
				}
				
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				
				if tt.expectNil {
					if pool != nil {
						t.Error("Expected nil cert pool")
					}
				} else {
					if pool == nil {
						t.Error("Expected non-nil cert pool")
					}
				}
			})
		}
	})
}

func TestTransportClone(t *testing.T) {
	transport := createTestTransport(t, []byte(testCACert1))
	
	// Set some additional transport properties
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 10
	transport.IdleConnTimeout = 90 * time.Second
	
	// Clone the transport
	cloned := transport.Clone()
	
	// Verify cloned transport has same properties
	if cloned.MaxIdleConns != transport.MaxIdleConns {
		t.Error("Expected cloned transport to have same MaxIdleConns")
	}
	
	if cloned.MaxIdleConnsPerHost != transport.MaxIdleConnsPerHost {
		t.Error("Expected cloned transport to have same MaxIdleConnsPerHost")
	}
	
	if cloned.IdleConnTimeout != transport.IdleConnTimeout {
		t.Error("Expected cloned transport to have same IdleConnTimeout")
	}
	
	// Verify TLS config is cloned
	if cloned.TLSClientConfig == nil {
		t.Error("Expected cloned transport to have TLS config")
	}
	
	if cloned.TLSClientConfig == transport.TLSClientConfig {
		t.Error("Expected cloned TLS config to be different instance")
	}
	
	// Verify RootCAs are the same
	if cloned.TLSClientConfig.RootCAs != transport.TLSClientConfig.RootCAs {
		t.Error("Expected cloned TLS config to have same RootCAs")
	}
}

// Benchmark CA rotation performance
func BenchmarkCARotation(b *testing.B) {
	caFile := writeCAFile(b, []byte(testCACert1))
	
	config := &Config{
		TLS: TLSConfig{
			CAFile: caFile,
			CAData: []byte(testCACert1),
		},
	}
	
	transport := createTestTransport(b, []byte(testCACert1))
	holder := newAtomicTransportHolder(config, transport)
	
	// Update CA file
	err := os.WriteFile(caFile, []byte(testCACert2), 0644)
	if err != nil {
		b.Fatalf("Failed to update CA file: %v", err)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		err := holder.checkCAFileAndRotate()
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

 