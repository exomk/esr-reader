/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (C) 2018  EXO Service Solutions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * You can contact us at contact4exo@exo.mk
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libpq-fe.h>
#include <nfc/nfc.h>
#include "log.h"

/******************************************** 
 *
 * ISO14443A (MIFARE) tag
 *
 *******************************************/
const nfc_modulation nmMifare = {
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106,
};

// APDU_HEADER + CARD_AID
const char *APDU_HEADER_CARD_AID = "\x00\xA4\x04\x00\x0C\xFA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A";
const int APDU_HEADER_CARD_AID_LEN = 17; // lenght in bytes

const char *STATUS_OK_CMD = "\x00\xD0\x00\x00";
const int STATUS_OK_CMD_LEN = 4;

/******************************************** 
 *
 * Global variables declaration.
 *
 *******************************************/
nfc_device *pnd;
nfc_target nt;

// Allocate only a pointer to nfc_context
nfc_context *context;

/******************************************** 
 *
 * Function prototype. 
 *
 *******************************************/
char* timestamp();
PGconn *create_db_connection();
int find_device_id(PGconn *conn, const char *uid);
void write_log(PGconn *conn, int device_id, char *register_type);
static void print_hex(const uint8_t *pbtData, const size_t szBytes);
char* build_hex_uid(const uint8_t *pbtData, const size_t szBytes);
int CardTransmit(nfc_device *pnd, uint8_t * capdu, size_t capdulen, uint8_t * rapdu, size_t * rapdulen);
void init_nfc_device();
void close_nfc_device();
char* read_device_uid(int argc, const char *argv[]);
void safe_exit(PGconn *conn);

/******************************************** 
 *
 * Create timestamp as string to store in DB.
 *
 *******************************************/
char* timestamp()
{
    char *timestamp;

    time_t now = time (NULL);
    timestamp = asctime (localtime (&now));

    return timestamp;
}

/******************************************** 
 *
 * Create database connection.
 *
 *******************************************/
PGconn *create_db_connection()
{
    const char *conn_string = "host=host port=port dbname=registrator user=user password=password";
    PGconn *conn;
    PGresult *res;
    int rows;

    conn = PQconnectdb(conn_string);

    // Check to see that the backend connection was successfully made
    if (PQstatus(conn) != CONNECTION_OK)
    {
        log_error(PQerrorMessage(conn)); 
        safe_exit(conn);
    }
    else 
    {
        log_info("Connection to the database succesfully established!");
    }

    return conn;
}

/******************************************** 
 *
 * Find DB device id to create log entry in the work_log table.
 *
 *******************************************/
int find_device_id(PGconn *conn, const char *uid)
{
    PGresult *res;
    const char *params[1];
    char *device_id_str;
    int device_id;


    params[0] = uid;
    res = PQexecParams(conn, "SELECT id FROM device WHERE uid=$1", 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK)
    {
        log_error(PQresultErrorMessage(res)); 
        safe_exit(conn);
    }

    if((device_id_str = PQgetvalue(res, 0, 0)) != NULL)
    {
        device_id = atoi(device_id_str);
    }

    PQclear(res);


    return device_id;
}

/******************************************** 
 *
 * Write log entry into the work_log table.
 *
 *******************************************/
void write_log(PGconn *conn, int device_id, char *register_type)
{
    PGresult *res;
    const char *params[3];
    char device_id_str[sizeof(int)];

    snprintf(device_id_str, sizeof(int), "%d", device_id); 
    params[0] = device_id_str;
    params[1] = timestamp();

    if(strcmp(register_type, "01") == 0)
    {
        params[2] = "REGISTER_IN";
    }
    else if(strcmp(register_type, "02") == 0)
    {
        params[2] = "BREAK";
    }
    else if(strcmp(register_type, "03") == 0)
    {
        params[2] = "REGISTER_OUT";
    }

    res = PQexecParams(conn, "INSERT INTO work_log(device_id, timestamp, register_type) VALUES($1, $2, $3)", 3, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK)
    {
        log_error(PQresultErrorMessage(res)); 
        safe_exit(conn);
    }

    PQclear(res);
}


/******************************************** 
 *
 * Print hexadecimal
 *
 *******************************************/
static void print_hex(const uint8_t *pbtData, const size_t szBytes)
{
    size_t  szPos;

    for (szPos = 0; szPos < szBytes; szPos++) {
        printf("%02x  ", pbtData[szPos]);
    }
    printf("\n");
}

/******************************************** 
 *
 * Extract bytes as hex string.
 *
 *******************************************/
char* extract_bytes_as_hex(const uint8_t *pbtData, size_t szPosStart, const size_t szBytes)
{
    size_t  szPos;
    size_t  startPos;
    size_t  endPos;
    char *buf = malloc(20 * sizeof(char));
    char *bufp = buf;

    startPos = szPosStart;
    endPos = szPosStart + szBytes;
    for (szPos = startPos; szPos < endPos; szPos++) {
        bufp += sprintf(bufp, "%02X", pbtData[szPos]);
    }
    buf[strlen(buf)] = '\0';

    return buf;
}

/******************************************** 
 *
 * Build device UID as hex string.
 *
 *******************************************/
char* build_hex_uid(const uint8_t *pbtData, const size_t szBytes)
{
    size_t  szPos;
    char *buf = malloc(20 * sizeof(char));
    char *bufp = buf;

    for (szPos = 0; szPos < szBytes; szPos++) {
        bufp += sprintf(bufp, "%02X", pbtData[szPos]);
    }
    buf[strlen(buf)] = '\0';

    return buf;
}


/******************************************** 
 *
 * Send APDU 
 *
 *******************************************/
int CardTransmit(nfc_device *pnd, uint8_t * capdu, size_t capdulen, uint8_t * rapdu, size_t * rapdulen)
{
    int res;
    size_t  szPos;

    printf("=> ");
    for (szPos = 0; szPos < capdulen; szPos++) {
        printf("%02X", capdu[szPos]);
    }
    printf("\n");
    if ((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, 500)) < 0) {
        return -1;
    } else {
        *rapdulen = (size_t) res;
        printf("<= ");
        for (szPos = 0; szPos < *rapdulen; szPos++) {
            printf("%02X", rapdu[szPos]);
        }
        printf("\n");

        return 0;
    }
}


/******************************************** 
 *
 * Initialize NFC device
 *
 *******************************************/
void init_nfc_device()
{
    const char *acLibnfcVersion; 

    // Initialize libnfc and set the nfc_context
    nfc_init(&context);
    if (context == NULL) {
        log_error("Unable to init libnfc (malloc)");
        exit(EXIT_FAILURE);
    }

    // Log libnfc version
    acLibnfcVersion = nfc_version();
    log_info_message("libnfc version: ", acLibnfcVersion);
    // Open, using the first available NFC device which can be in order of selection:
    //   - default device specified using environment variable or
    //   - first specified device in libnfc.conf (/etc/nfc) or
    //   - first specified device in device-configuration directory (/etc/nfc/devices.d) or
    //   - first auto-detected (if feature is not disabled in libnfc.conf) device
    pnd = nfc_open(context, NULL);

    if (pnd == NULL) {
        printf("ERROR: %s\n", "Unable to open NFC device.");
        exit(EXIT_FAILURE);
    }

    // Set opened NFC device to initiator mode
    if (nfc_initiator_init(pnd) < 0) {
        nfc_perror(pnd, "nfc_initiator_init");
        exit(EXIT_FAILURE);
    }

    log_info_message("NFC reader opened: ", nfc_device_get_name(pnd));
}


/******************************************** 
 *
 * Close NFC device
 *
 *******************************************/
void close_nfc_device()
{
    // Close NFC device
    nfc_close(pnd);

    // Release the context
    nfc_exit(context);
}

void send_status_ok_cmd()
{
    // transmit APDU
    uint8_t tapdu[264];
    size_t tapdulen;

    // receive APDU
    uint8_t rapdu[264];
    size_t rapdulen;

    // Select application
    memcpy(tapdu, STATUS_OK_CMD, STATUS_OK_CMD_LEN);
    tapdulen = STATUS_OK_CMD_LEN;
    rapdulen = sizeof(rapdu);

    CardTransmit(pnd, tapdu, tapdulen, rapdu, &rapdulen);
}

/******************************************** 
 * 
 * Safe exit from application after close DB connection.
 *
 *******************************************/
void safe_exit(PGconn *conn)
{
    PQfinish(conn);
    exit(1);
}

/******************************************** 
 *
 * Registrator application entry point.
 *
 *******************************************/
int main(int argc, const char* argv[])
{
    PGconn *conn;
    char *uid;
    int device_id;

    log_info("*************** Registrator application started!  ***************"); 
    // connect to DB
    conn = create_db_connection();

    // init NFC device
    init_nfc_device();
    
    // scan device
    while(1)
    {
        // Read device UID and register type from the device.

        // transmit APDU
        uint8_t tapdu[264];
        size_t tapdulen;

        // receive APDU
        uint8_t rapdu[264];
        size_t rapdulen;

        // UID
        char *uid;

        // Register type
        char *register_type;

        while (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0);
    
        // Select application
        memcpy(tapdu, APDU_HEADER_CARD_AID, APDU_HEADER_CARD_AID_LEN);
        tapdulen = APDU_HEADER_CARD_AID_LEN;
        rapdulen = sizeof(rapdu);

        if (CardTransmit(pnd, tapdu, tapdulen, rapdu, &rapdulen) < 0) 
        {
	    uid = NULL;
            // exit(EXIT_FAILURE);
        }

        if (rapdulen < 2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00)
        {
	    uid = NULL;
            // exit(EXIT_FAILURE);
        }

        // extract check status
        register_type = extract_bytes_as_hex(rapdu, rapdulen - 3, 1);

        // do not read latest 2 bytes 9000 "OK" status word
        uid = build_hex_uid(rapdu, rapdulen - 3);
        if(uid != NULL)
        {
            device_id = find_device_id(conn, uid);
            if(device_id > 0) {
                send_status_ok_cmd();
            }
            write_log(conn, device_id, register_type);
        }
    }
    
    // close DB connection
    free(uid);
    PQfinish(conn);

    // close NFC device
    close_nfc_device();

    log_info("*************** Registrator application stoped!  ***************"); 

    return(0);
}

