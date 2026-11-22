// Trusted devices: register, list and revoke your users' devices from your
// server (DevicesClient), and sign requests from a Node device such as a
// kiosk (createDeviceSigner). Also at 'shield360/devices'.
export { DevicesClient, DeviceError, devices } from './client';
export type { DeviceTrust, DeviceScope, RegisterDeviceInput, DeviceInfo, ConfirmPairingOptions, DevicesOptions } from './client';
export { DeviceSigner, createDeviceSigner, signingMessage, passExpiry, DEVICE_HEADER, DEVICE_PASS_HEADER } from './signer';
export type { DeviceSignerOptions, PairingStart } from './signer';
