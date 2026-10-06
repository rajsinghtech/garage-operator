// Package contract runs the operator's Garage Admin API client against real
// Garage processes. The tests carry the garagecontract build tag and need a
// garage binary: GARAGE_BIN=/path/to/garage make test-contract
// (hack/fetch-garage-binary.sh extracts one from a dxflrs/garage image).
package contract
