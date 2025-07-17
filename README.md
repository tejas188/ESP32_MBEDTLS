# ESP32 Secure Device Provisioning System

This firmware enables secure device provisioning for ESP32 microcontrollers, implementing certificate-based authentication and secure communication with backend servers.

## Features

- **Secure Key Generation**: ECC P-256 private key generation using mbedTLS
- **Certificate Management**: 
  - CSR generation with device-specific subject (UID-based)
  - Certificate storage in DER format (EEPROM)
  - Certificate conversion to PEM format
- **Secure Communication**:
  - TLS 1.2/1.3 support with server verification
  - CA certificate management (SPIFFS)
- **Device Identity**:
  - Unique device UID generation
  - MAC address retrieval
- **WiFi Management**: 
  - Credential storage in SPIFFS
  - Automatic reconnection
- **Serial Command Interface**: Human-readable control protocol

## Hardware Requirements

- ESP32 development board
- SPI Flash (4MB recommended)
- EEPROM (emulated or physical)

## Dependencies

| Library | Purpose |
|---------|---------|
| `WiFi.h` | WiFi connectivity |
| `WiFiClientSecure.h` | TLS communication |
| `SPIFFS.h` | Certificate storage |
| `EEPROM.h` | Key/certificate storage |
| `mbedtls` | Cryptographic operations |
| `Base64.h` | Certificate encoding |

## Setup Instructions

1. **Load CA Certificate**:
   - Place `ca_cert.crt` in SPIFFS root directory
   - Use ESP32 Sketch Data Upload tool

2. **Flash Firmware**:
   - Compile and upload sketch to ESP32
   - Open serial monitor at 115200 baud

3. **Initial Configuration**:
```plaintext
CONNECT:<SSID>,<Password>,<ServerIP>,<Port>
Example: CONNECT:MyWiFi,secret123,192.168.1.100,8443

GKC:<OrganizationName>
Example: GKC:MyCompany
.
.
.
.
