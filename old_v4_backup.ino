#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <SPIFFS.h>
#include <EEPROM.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/pem.h"
#include "mbedtls/base64.h"
#include "mbedtls/bignum.h"
#include "mbedtls/error.h"
#include "mbedtls/x509.h"
#include "mbedtls/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "FS.h"
#include <Base64.h>

// Global variables to store connection information
String ssid = "";
String password = "";
String server_ip = "";
int server_port = 0;
String organization = "";

bool parseConnectionString(String input) {
    if (!input.startsWith("CONNECT:")) {
        return false;
    }

    input = input.substring(8); // Remove "CONNECT:" prefix
    int firstComma = input.indexOf(',');
    int secondComma = input.indexOf(',', firstComma + 1);
    int thirdComma = input.indexOf(',', secondComma + 1);

    if (firstComma == -1 || secondComma == -1 || thirdComma == -1) {
        Serial.println("ERR:Invalid connection string format");
        return false;
    }

    ssid = input.substring(0, firstComma);
    ssid.trim();  // Apply trim after extraction

    password = input.substring(firstComma + 1, secondComma);
    password.trim();

    server_ip = input.substring(secondComma + 1, thirdComma);
    server_ip.trim();

    String portStr = input.substring(thirdComma + 1);
    portStr.trim();

    server_port = portStr.toInt();

    // Basic validation
    if (ssid.isEmpty() || server_ip.isEmpty() || server_port <= 0 || server_port > 65535) {
        Serial.println("ERR:Invalid connection parameters");
        return false;
    }
    return true;
}

bool parseOrganizationCommand(String input) {
    if (input.startsWith("GKC:")) {
        organization = input.substring(4); // Remove "GKC:" prefix
        organization.trim(); // Trim whitespace

        if (organization.length() > 0) {
            return true;
        } else {
            Serial.println("ERR:Invalid organization name");
        }
    }
    return false;
}

// Function to read CA certificate from SPIFFS
String readCACert() {
    if (!SPIFFS.begin(true)) {
        Serial.println("ERR:An Error has occurred while mounting SPIFFS");
        return String();
    }
    File file = SPIFFS.open("/ca_cert.crt", "r");
    if (!file) {
        Serial.println("ERR:Failed to open certificate.crt file");
        return String();
    }

    String ca_cert = file.readString();
    file.close();
    return ca_cert;
}

// Function to print CA certificate
void printCACert() {
    String ca_cert = readCACert();
    if (ca_cert.isEmpty()) {
        Serial.println("ERR:CA certificate is empty or could not be read");
    } else {
        //Serial.println("CA certificate read from SPIFFS:");
        //Serial.println(ca_cert);
    }
}

// Function to print key (public or private)
void print_key(const char *title, mbedtls_pk_context *key, int is_public) {
    unsigned char buf[2048];
    size_t len = sizeof(buf);

    if (is_public) {
        mbedtls_pk_write_pubkey_pem(key, buf, len);
    } else {
        mbedtls_pk_write_key_pem(key, buf, len);
    }
}

// Function to get ESP32 UID
String getESP32UID() {
    uint64_t chipid = ESP.getEfuseMac();
    char uid[17];
    snprintf(uid, sizeof(uid), "%04X%08X", (uint16_t)(chipid >> 32), (uint32_t)chipid);
    return String(uid);
}

// Function to get MAC address
String getMACAddress() {
    uint8_t mac[6];
    WiFi.macAddress(mac);
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(mac_str);
}

bool isWiFiConnected() {
    return WiFi.status() == WL_CONNECTED;
}

String boolToStr(bool value) {
    return value ? "true" : "false";
}

// Function to print device information in string
void printDeviceInfo() {
    bool status = isWiFiConnected();
    String cstatus = boolToStr(status);
    String ssid,password,chipModel,macAddress,ipAddress,uid;
    
    if(cstatus == "false"){
      if (!loadWiFiCredentials(ssid, password, server_ip, server_port)) {
        // Serial.println("Failed to load WiFi credentials from SPIFFS");
        return;
      }
       WiFi.begin(ssid.c_str(), password.c_str());
       int attempts = 0;
       while (WiFi.status() != WL_CONNECTED && attempts < 20) {
        delay(500);
        // Serial.print("STATUS:Waiting for connection...\n");
        attempts++;
        }
     if (WiFi.status() == WL_CONNECTED) {
        chipModel = ESP.getChipModel();//"ESP32"; // Change this if you need a different model string
        macAddress = getMACAddress();
        ipAddress = WiFi.localIP().toString();
        uid = getESP32UID();
        }
    }
    else{
          chipModel = ESP.getChipModel();//"ESP32"; // Change this if you need a different model string
          macAddress = getMACAddress();
          ipAddress = WiFi.localIP().toString();
          uid = getESP32UID();
    }
    printf("Chip Model:%s,MAC Address:%s,IP Address:%s,UID:%s\n", 
                  chipModel.c_str(), macAddress.c_str(), ipAddress.c_str(), uid.c_str());
}

void readUIDandCSR() {
    String uid = getESP32UID();   // Get the UID
    String csr = readCSRFromFile();  // Read the CSR from file

    if (csr.isEmpty()) {
        Serial.println("ERR:CSR is empty or could not be read.");
        return;
    }

    // Print the UID and CSR using Serial.printf() similar to the device info printout
    Serial.printf("UID:%s,CSR:%s\n", uid.c_str(), csr.c_str());
}


// Function to get user input from Serial
String getInput(String prompt) {
    Serial.println(prompt);
    while (Serial.available() == 0) {
        delay(100);
    }
    return Serial.readStringUntil('\n');
}

void saveDERCertificateToEEPROM(const unsigned char* derCertificate, size_t derLength) {
    EEPROM.begin(4096);
    uint32_t start_address = 1024;  // Adjust start address if needed

    // Save the length of the DER certificate
    EEPROM.writeUInt(start_address, derLength);

    // Save the DER certificate
    for (size_t i = 0; i < derLength; i++) {
        EEPROM.write(start_address + 4 + i, derCertificate[i]);
    }

    EEPROM.commit();
    //Serial.println("DER certificate saved to EEPROM successfully.");
}

void savePrivateKeyToEEPROM(mbedtls_pk_context pk) {
    unsigned char key_buf[32];
    size_t key_len = sizeof(key_buf);

    int ret = mbedtls_mpi_write_binary(&mbedtls_pk_ec(pk)->private_d, key_buf, mbedtls_mpi_size(&mbedtls_pk_ec(pk)->private_d));
    if (ret != 0) {
        Serial.printf("ERR:Failed to write private key d value, error code: %d\n", ret);
        return;
    }

    EEPROM.begin(4096);
    uint32_t key_start = 0;  // Start of EEPROM

    // Save the length of the key
    // Save the key
    for (size_t i = 0; i < sizeof(key_buf); i++) {
        EEPROM.write(key_start + 4 + i, key_buf[i]);
    }

    EEPROM.commit();
    //Serial.println("Private key saved to EEPROM successfully.");
}

void readPrivateKeyFromEEPROM() {
    EEPROM.begin(4096);
    uint32_t key_start = 0;
    int key_len = 32;
    Serial.printf("STATUS:Read private key length: %d\n", key_len);

    if (key_len > 2048 || key_len == 0) {
        Serial.println("ERR:Invalid key length read from EEPROM");
    }

    Serial.println("Private key read from EEPROM:");
    for (size_t i = 0; i < key_len; i++) {
        printf("%02X", EEPROM.read(key_start + 4 + i));
    }
    printf("\n");
}

void saveWiFiAndServerInfo(const String& ssid, const String& password, const String& serverIP, int serverPort) {
    File file = SPIFFS.open("/wifi_credentials.txt", FILE_WRITE);

    if (!file) {
        Serial.println("ERR:Failed to open file for writing");
        return;
    }
    file.println(ssid);
    file.println(password);
    file.println(serverIP);
    file.println(serverPort);
    file.close();
    //Serial.println("STATUS:Network information saved");
}

bool loadWiFiCredentials(String &ssid, String &password, String &serverIP, int &serverPort) {
    File file = SPIFFS.open("/wifi_credentials.txt", FILE_READ);

    if (!file) {
        Serial.println("ERR:Failed to open file for reading");
        return false;
    }

    ssid = file.readStringUntil('\n');
    password = file.readStringUntil('\n');
    serverIP = file.readStringUntil('\n');
    String portStr = file.readStringUntil('\n');
    
    // Remove any newline characters from the strings
    ssid.trim();
    password.trim();
    serverIP.trim();
    portStr.trim();

    // Convert port string to integer
    serverPort = portStr.toInt();

    file.close();
    //Serial.println("STATUS:Network information loaded");
    return true;
}

void initializeWiFi() {
    WiFi.begin(ssid.c_str(), password.c_str());

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20) {
        delay(500);
        Serial.print("STATUS:Waiting for connection...\n");
        attempts++;
    }

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("STATUS:Failed to connect WiFi\n");
        return;
    }
    Serial.println("STATUS:WiFi Connected\n");

    saveWiFiAndServerInfo(ssid, password, server_ip, server_port);
}

// Function to generate key and CSR
void generateKeyAndCSR() {
    int ret;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509write_csr csr;
    unsigned char csr_buf[2048];
    const char *pers = "gen_key";
    unsigned char buf[64];

    mbedtls_pk_init(&key);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509write_csr_init(&csr);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        Serial.printf("ERR:mbedtls_ctr_drbg_seed returned %d\n", ret);
        return;
    }

    ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        Serial.printf("ERR:mbedtls_pk_setup returned %d\n", ret);
        return;
    }
 
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), mbedtls_ctr_drbg_random, &ctr_drbg);
       if (ret != 0) {
        Serial.printf("ERR:mbedtls_ecc_genkey returned %d\n", ret);
        return;
    }
    //print_key("Private Key:", &key, 0);
    //printf("Private key:\n");
    ret = mbedtls_mpi_write_binary(&mbedtls_pk_ec(key)->private_d, buf, mbedtls_mpi_size(&mbedtls_pk_ec(key)->private_d));
    for (size_t i = 0; i <mbedtls_mpi_size(&mbedtls_pk_ec(key)->private_d); i++) {
        //printf("%02X", buf[i]);
    }
    //printf("\n");

    savePrivateKeyToEEPROM(key);

    //print_key("Public Key:", &key, 1);

    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&csr, &key);

    String uid = getESP32UID();
    // Serial.printf("UID:%s\n", uid.c_str());

    //String organization = getInput("Please enter Organization (O):");
    //String country = getInput("Please enter Country (C):");
    const char* country = "IN";

    String subject_name = "CN=" + uid + ",O=" + organization + ",C=" + country;
    ret = mbedtls_x509write_csr_set_subject_name(&csr, subject_name.c_str());
    if (ret != 0) {
        Serial.printf("ERR:mbedtls_x509write_csr_set_subject_name returned %d\n", ret);
        return;
    }

    ret = mbedtls_x509write_csr_pem(&csr, csr_buf, sizeof(csr_buf),
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret < 0) {
        Serial.printf("ERR:mbedtls_x509write_csr_pem returned %d\n", ret);
        return;
    }

    //Serial.println("CSR generated successfully:");
    //Serial.println((char *) csr_buf);

    File file = SPIFFS.open("/csr.pem", FILE_WRITE);
    if (!file) {
        Serial.println("ERR:Failed to open spiffs file for writing");
    } else {
        file.print((char *)csr_buf);
        file.close();
        //Serial.println("CSR saved to /csr.pem");
    }

    mbedtls_pk_free(&key);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509write_csr_free(&csr);
}

void sendCSRAndReceiveCertificate() {

    bool status = isWiFiConnected();
    String cstatus = boolToStr(status);

    // If not connected, attempt to load credentials and connect
    if (cstatus == "false") {
        if (!loadWiFiCredentials(ssid, password, server_ip, server_port)) {
            Serial.println("ERR: Failed to load WiFi credentials");
            return;
        }

        // Attempt to connect to WiFi using loaded credentials
        WiFi.begin(ssid.c_str(), password.c_str());
        int attempts = 0;

        while (WiFi.status() != WL_CONNECTED && attempts < 20) {
            delay(500);
            attempts++;
        }

        // Check if WiFi connected successfully
        if (WiFi.status() == WL_CONNECTED) {

            WiFiClientSecure client;
            // Load CA certificate for secure connection
            String ca_cert = readCACert();
            if (ca_cert.isEmpty()) {
                Serial.println("ERR: CA certificate is empty or could not be read");
                return;
            }

            client.setCACert(ca_cert.c_str());

            // Attempt to connect to the TLS server
            if (client.connect(server_ip.c_str(), server_port)) {
                //Serial.println("STATUS: Connected to TLS server");

                // Read CSR from file and create an HTTP POST request
                String csr = readCSRFromFile();
                String post_request = createHTTPPostRequest(csr);
                client.print(post_request);
                //Serial.println("STATUS: HTTP POST request sent");

                // Wait for server response
                String response = waitForServerResponse(client);
                //Serial.println("STATUS: Server response received");
                Serial.println(response);

                // Read the response body from the server
                String responseBody = "";
                while (client.available()) {
                    char c = client.read();
                    responseBody += c;
                }
                //Serial.println(responseBody);

                // Process the received certificate or error
                processCertificateResponse(response);
            } else {
                Serial.println("ERR: Connection to server failed!");
                Serial.print("Last error: ");
                // Optional: Print the last error (commented out)
                Serial.println(client.lastError(nullptr, 0));
            }
        } else {
            Serial.println("ERR: Failed to connect to WiFi!");
        }
    }
    else
    {
            WiFiClientSecure client;
            // Load CA certificate for secure connection
            String ca_cert = readCACert();
            if (ca_cert.isEmpty()) {
                Serial.println("ERR: CA certificate is empty or could not be read");
                return;
            }

            client.setCACert(ca_cert.c_str());

            // Attempt to connect to the TLS server
            if (client.connect(server_ip.c_str(), server_port)) {
                //Serial.println("STATUS:Connected to TLS server");

                // Read CSR from file and create an HTTP POST request
                String csr = readCSRFromFile();
                String post_request = createHTTPPostRequest(csr);
                client.print(post_request);
                //Serial.println("STATUS:HTTP POST request sent");

                // Wait for server response
                String response = waitForServerResponse(client);
                //Serial.println("STATUS: Server response received");
                Serial.println(response);

                // Read the response body from the server
                String responseBody = "";
                while (client.available()) {
                    char c = client.read();
                    responseBody += c;
                }
                //Serial.println(responseBody);

                // Process the received certificate or error
                processCertificateResponse(response);
            } else {
                Serial.println("ERR: Connection to server failed!");
                Serial.print("Last error: ");
                Serial.println(client.lastError(nullptr, 0));
            }
    }
}

// Function to read CSR from file
String readCSRFromFile() {
    File file = SPIFFS.open("/csr.pem", "r");
    if (!file) {
        Serial.println("ERR:Failed to open CSR file");
        return String();
    }
    String csr = file.readString();
    file.close();
    return csr;
}

void readRawResponse() {
    if (!SPIFFS.begin(true)) {
        Serial.println("ERR:An Error has occurred while mounting SPIFFS");
        return;
    }

    File file = SPIFFS.open("/raw_response.txt", FILE_READ);
    if (!file) {
        Serial.println("ERR:Failed to open raw_response.txt");
        return;
    }

    //Serial.println("STATUS:Contents of /raw_response.txt:");
    while (file.available()) {
        String line = file.readStringUntil('\n');
        Serial.println(line);
    }
    file.close();
}

// Function to create HTTP POST request for main server
String createHTTPPostRequest(const String& csr) {
    String post_request = "POST /generate_certificate/ HTTP/1.1\r\n";
    post_request += "Host: " + String(server_ip) + ":8443\r\n";
    post_request += "Content-Type: text/plain\r\n";
    post_request += "Content-Length: " + String(csr.length()) + "\r\n";
    post_request += "Connection: close\r\n\r\n";
    post_request += csr + "\r\n";
    return post_request;
}

String waitForServerResponse(WiFiClientSecure& client) {
    String response = "";
    bool headersEnded = false;
    while (client.connected()) {
        String line = client.readStringUntil('\n');
        if (!headersEnded) {
            if (line == "\r") {
                headersEnded = true;
            }
        } else {
            response += line + "\n";
        }
        if (line.length() == 0 && headersEnded) {
            break;
        }
    }
    return response;
}

void convertPEMToDER(const String& pemCertificate, unsigned char* derBuffer, size_t* derLength) {
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);

    // Convert the PEM certificate to DER format
    int ret = mbedtls_x509_crt_parse(&cert, (const unsigned char*)pemCertificate.c_str(), pemCertificate.length() + 1);
    
    if (ret != 0) {
        Serial.printf("Failed to parse certificate, mbedtls_x509_crt_parse returned -0x%04X\n", -ret);
        mbedtls_x509_crt_free(&cert);
        return;
    }

    // Convert to DER
    *derLength = cert.raw.len;;
    memcpy(derBuffer, cert.raw.p, *derLength); // Copy raw DER data

    mbedtls_x509_crt_free(&cert); // Clean up
}

void readDERCertificateFromEEPROM(unsigned char* derCertificate, size_t* derLength) {
    EEPROM.begin(4096);
    uint32_t start_address = 1024;  // Same start address used while saving

    // Read the length of the DER certificate
    *derLength = EEPROM.readUInt(start_address);

    // Read the DER certificate
    for (size_t i = 0; i < *derLength; i++) {
        derCertificate[i] = EEPROM.read(start_address + 4 + i);
    }

    //Serial.println("DER certificate read from EEPROM successfully.");
}

String convertDERToPEM(const unsigned char* derCertificate, size_t derLength) {
    String pem = "-----BEGIN CERTIFICATE-----\n";
    String encoded = base64::encode(derCertificate, derLength);  // Use your base64 encoding method

    // Split encoded string into lines of 64 characters each
    for (size_t i = 0; i < encoded.length(); i += 64) {
        pem += encoded.substring(i, i + 64) + "\n";
    }

    pem += "-----END CERTIFICATE-----\n";
    return pem;
}

void readAndConvertCertificate() {
    unsigned char derCertificate[2048]; // Adjust size as needed
    size_t derLength = 0; 

    // Read the DER certificate from EEPROM
    readDERCertificateFromEEPROM(derCertificate, &derLength);

    // Convert to PEM format
    String pemCertificate = convertDERToPEM(derCertificate, derLength);

    // Display or utilize the PEM formatted certificate
    //Serial.println("PEM Certificate:");
    Serial.println(pemCertificate);
}

void processCertificateResponse(const String& responseBody) {
    if (responseBody.indexOf("-----BEGIN CERTIFICATE-----") != -1 &&
        responseBody.indexOf("-----END CERTIFICATE-----") != -1) {

        int startIndex = responseBody.indexOf("-----BEGIN CERTIFICATE-----");
        int endIndex = responseBody.indexOf("-----END CERTIFICATE-----") + 25;
        if (startIndex != -1 && endIndex != -1) {
            String certificate = responseBody.substring(startIndex, endIndex);
            
            //saveCertificateToEEPROM(certificate);
        
            // Convert to DER format
            unsigned char derCertificate[2048]; // Adjust size as needed
            size_t derLength = 0;
            convertPEMToDER(certificate, derCertificate, &derLength);

            //Serial.println("Certificate saved to EEPROM successfully.");
            //Serial.print("DER length: ");
            //Serial.println(derLength); // Display the length of the DER certificate

            // Save the DER certificate to EEPROM
            saveDERCertificateToEEPROM(derCertificate, derLength);

        } else {
            Serial.println("ERR:Unable to parse certificate from responseBody. Certificate markers not found.");
        }
    } else {
        //Serial.println("ERR:Certificate markers not found in responseBody.");
        //handleNoCertificateResponse(responseBody);
        //Serial.println(responseBody);
    }
}

// Function to handle case when no certificate is found in response
void handleNoCertificateResponse(const String& responseBody) {
    Serial.printf("Received %d bytes\n", responseBody.length());
    Serial.println("Raw response received from server:");
    Serial.println(responseBody);
    Serial.println("First 200 characters of response:");
    Serial.println(responseBody.substring(0, min(200, (int)responseBody.length())));
    
    File responseFile = SPIFFS.open("/raw_response.txt", FILE_WRITE);
    if (responseFile) {
        responseFile.print(responseBody);
        responseFile.close();
        Serial.println("Raw response saved to /raw_response.txt for further analysis");
    } else {
        Serial.println("Failed to save raw response to /raw_response.txt");
    }
}

void setup() {
    Serial.begin(115200);

    if (!SPIFFS.begin(true)) {
        Serial.println("ERR:An Error has occurred while mounting SPIFFS");
        return;
    }
    printCACert();
}

void loop() {
    if (Serial.available() > 0) {
        String input = Serial.readStringUntil('\n');
        input.trim();
        if (parseConnectionString(input)) {
            initializeWiFi();   
        } else if (input == "GI") {
            printDeviceInfo(); 
        } else if (parseOrganizationCommand(input)) {//(input == "GKC") {
            generateKeyAndCSR();
            readUIDandCSR();
        } else if (input == "GDC") {
            sendCSRAndReceiveCertificate();
        } else if (input == "RCE") {
            //readCertificateFromEEPROM();
            readAndConvertCertificate();
        } else if (input == "GPK") {
            readPrivateKeyFromEEPROM();
        } else if (input == "RRR") {  // New command to Read Raw Response
            readRawResponse();
        } else {
            Serial.println("Invalid input...");
        }
    }
}

