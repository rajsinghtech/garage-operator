/*
Copyright 2026 Raj Singh.

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

package garageconfig

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestManagedBindPort(t *testing.T) {
	tests := []struct {
		name    string
		address string
		port    int32
		want    int32
		wantErr bool
	}{
		{name: "default", want: 3900},
		{name: "configured port", port: 4900, want: 4900},
		{name: "IPv4 wildcard overrides port", address: "0.0.0.0:5900", port: 4900, want: 5900},
		{name: "IPv6 wildcard overrides port", address: "[::]:5900", want: 5900},
		{name: "port only", address: ":5900", wantErr: true},
		{name: "loopback", address: "127.0.0.1:5900", wantErr: true},
		{name: "hostname", address: "garage:5900", wantErr: true},
		{name: "Unix socket", address: "unix:///run/garage.sock", wantErr: true},
		{name: "zero", address: "0.0.0.0:0", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ManagedBindPort(tt.address, tt.port, 3900, "spec.s3Api.bindAddress")
			if (err != nil) != tt.wantErr {
				t.Fatalf("ManagedBindPort() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("ManagedBindPort() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGarageValueValidation(t *testing.T) {
	for _, value := range []string{"none", "-99", "-1", "0", "1", "22"} {
		if err := ValidateCompressionLevel(value, "compression"); err != nil {
			t.Errorf("compression level %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"-100", "23", "bogus"} {
		if err := ValidateCompressionLevel(value, "compression"); err == nil {
			t.Errorf("compression level %q accepted", value)
		}
	}
	if err := ValidateRPCDuration(time.Millisecond, "timeout"); err != nil {
		t.Fatalf("1ms RPC duration rejected: %v", err)
	}
	if err := ValidateRPCDuration(time.Millisecond-time.Nanosecond, "timeout"); err == nil {
		t.Fatal("sub-millisecond RPC duration accepted")
	}
	for _, value := range []string{"600s", "10m", "1h 30m", "0.5h"} {
		if err := ValidateMetadataSnapshotInterval(value, "snapshot"); err != nil {
			t.Errorf("snapshot interval %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"599s", "9m 59s", "invalid"} {
		if err := ValidateMetadataSnapshotInterval(value, "snapshot"); err == nil {
			t.Errorf("snapshot interval %q accepted", value)
		}
	}
}

func TestValidateGroupVolumeDataSource(t *testing.T) {
	group := "kopiur.example.io"
	valid := &corev1.TypedObjectReference{APIGroup: &group, Kind: "Restore", Name: "restore"}
	if err := ValidateGroupVolumeDataSource(valid, "storage", "spec.storage.data.dataSourceRef"); err != nil {
		t.Fatalf("valid group source rejected: %v", err)
	}
	if err := ValidateGroupVolumeDataSource(nil, "storage", "spec.storage.data.dataSourceRef"); err != nil {
		t.Fatalf("nil source rejected: %v", err)
	}
	core := &corev1.TypedObjectReference{Kind: "PersistentVolumeClaim", Name: "disk"}
	if err := ValidateGroupVolumeDataSource(core, "storage", "spec.storage.data.dataSourceRef"); err == nil {
		t.Fatal("core PVC source accepted")
	}
	other := "other"
	cross := valid.DeepCopy()
	cross.Namespace = &other
	if err := ValidateGroupVolumeDataSource(cross, "storage", "spec.storage.data.dataSourceRef"); err == nil {
		t.Fatal("cross-namespace source accepted")
	}
}

func TestValidateAdminAPIEndpoint(t *testing.T) {
	for _, value := range []string{"http://garage:3903", "https://garage.example/proxy"} {
		if err := ValidateAdminAPIEndpoint(value, "endpoint"); err != nil {
			t.Errorf("endpoint %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{
		"garage:3903", "ftp://garage:3903", "http:///missing-host", "http://:3903",
		"http://garage:0", "http://garage:99999", "http://garage:3903?q=1", " http://garage:3903",
	} {
		if err := ValidateAdminAPIEndpoint(value, "endpoint"); err == nil {
			t.Errorf("endpoint %q accepted", value)
		}
	}
}
