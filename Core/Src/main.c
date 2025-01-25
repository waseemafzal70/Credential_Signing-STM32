/* Includes ------------------------------------------------------------------*/
#include <string.h>
#include "main.h"
#include "cmox_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#define MAX_TRIPLES 100
#define MAX_MESSAGE_SIZE 2048
#define OUTPUT_FILE "rdf_output.json"
#define hexSignature_MAX_SIZE 1024
char hexSignature[hexSignature_MAX_SIZE];

// RDFTriple "class"
typedef struct {
    char *subject;
    char *predicate;
    char *object;
} RDFTriple;

// RDFGraph "class"
typedef struct {
    RDFTriple triples[MAX_TRIPLES];
    int size;
} RDFGraph;

// RDFProcessor "class"
typedef struct {
    RDFGraph *graph;
} RDFProcessor;

char *trimWhitespace(const char *str) {
    if (!str) return NULL;
    char *mutableStr = strdup(str);
    if (!mutableStr) return NULL;

    char *start = mutableStr;
    char *end;

    while (isspace((unsigned char)*start)) start++;

    if (*start == 0) {
        *mutableStr = '\0';
        return mutableStr;
    }

    end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) end--;

    end[1] = '\0';
    return strdup(start);
}

// RDFGraph "constructor" to initialize the graph
RDFGraph *RDFGraph_new() {
    RDFGraph *graph = (RDFGraph *)malloc(sizeof(RDFGraph));
    graph->size = 0;
    return graph;
}

// Add a triple to the RDF graph
void RDFGraph_addTriple(RDFGraph *graph, const char *subject, const char *predicate, const char *object) {
    if (graph->size < MAX_TRIPLES) {
        graph->triples[graph->size].subject = strdup(trimWhitespace(subject));
        graph->triples[graph->size].predicate = strdup(trimWhitespace(predicate));
        graph->triples[graph->size].object = strdup(trimWhitespace(object));
        graph->size++;
    }
}

// Sorting triples
int compareTriples(const void *a, const void *b) {
    RDFTriple *tripleA = (RDFTriple *)a;
    RDFTriple *tripleB = (RDFTriple *)b;
    int subjectCmp = strcmp(tripleA->subject, tripleB->subject);
    if (subjectCmp != 0) return subjectCmp;
    int predicateCmp = strcmp(tripleA->predicate, tripleB->predicate);
    if (predicateCmp != 0) return predicateCmp;
    return strcmp(tripleA->object, tripleB->object);
}

// Canonicalize the RDF graph
void RDFGraph_canonicalize(RDFGraph *graph) {
    qsort(graph->triples, graph->size, sizeof(RDFTriple), compareTriples);
}

// Serialize the RDF graph to JSON-LD format
void RDFGraph_serializeToJsonLD(RDFGraph *graph, char *output) {
    char context[] = "[\"http://schema.org/\", \"https://w3id.org/security/v2\"]";
    char description[] = "\"description\": \"Hello World!\"";

    snprintf(output, MAX_MESSAGE_SIZE, "{\n  \"@context\": %s,\n  %s,\n  \"proof\": {\n", context, description);

    for (int i = 0; i < graph->size; i++) {
        if (strcmp(graph->triples[i].predicate, "ProofCreated") == 0) {
            snprintf(output + strlen(output), MAX_MESSAGE_SIZE - strlen(output),
                     "    \"created\": \"%s\",\n", "2025-10-23T05:50:16Z");
        } else if (strcmp(graph->triples[i].predicate, "ProofType") == 0) {
            snprintf(output + strlen(output), MAX_MESSAGE_SIZE - strlen(output),
                     "    \"type\": \"%s\",\n", graph->triples[i].object);
        } else if (strcmp(graph->triples[i].predicate, "VerificationMethod") == 0) {
            snprintf(output + strlen(output), MAX_MESSAGE_SIZE - strlen(output),
                     "    \"verificationMethod\": \"%s\",\n", graph->triples[i].object);
        } else if (strcmp(graph->triples[i].predicate, "ProofPurpose") == 0) {
            snprintf(output + strlen(output), MAX_MESSAGE_SIZE - strlen(output),
                     "    \"proofPurpose\": \"%s\",\n", graph->triples[i].object);
        } else if (strcmp(graph->triples[i].predicate, "jws") == 0) {
            snprintf(output + strlen(output), MAX_MESSAGE_SIZE - strlen(output),
                     "    \"jws\": \"%s\"\n", hexSignature);
        }
    }
    snprintf(output + strlen(output), MAX_MESSAGE_SIZE - strlen(output), "  }\n}\n");
}

RDFProcessor *RDFProcessor_new(RDFGraph *graph) {
    RDFProcessor *processor = (RDFProcessor *)malloc(sizeof(RDFProcessor));
    processor->graph = graph;
    return processor;
}

// Process the RDF graph using RDFProcessor
void RDFProcessor_process(RDFProcessor *processor, char *output) {
    RDFGraph_canonicalize(processor->graph);
    RDFGraph_serializeToJsonLD(processor->graph, output);
}

void RDFGraph_free(RDFGraph *graph) {
    for (int i = 0; i < graph->size; i++) {
        free(graph->triples[i].subject);
        free(graph->triples[i].predicate);
        free(graph->triples[i].object);
    }
    free(graph);
}

void RDFProcessor_free(RDFProcessor *processor) {
    free(processor);
}

// Save the RDF graph to JSON file
void saveRDF(const char *output) {
    FILE *file = fopen(OUTPUT_FILE, "w");
    if (file != NULL) {
        fprintf(file, "%s", output);
        fclose(file);
        UART_Print("\nOutput saved to %s\n", OUTPUT_FILE);
    } else {
    	UART_Print("\nFailed to save output to file.\n");
    }
}

// Function to process the RDF graph and store it in the Message variable
void processRDF(char *output) {
    RDFGraph *graph = RDFGraph_new();

    RDFGraph_addTriple(graph, " credential1  ", " ProofType ", "EcdsaSignature2018");
    RDFGraph_addTriple(graph, " credential1 ", " ProofCreated ", "2025-10-23T05:50:16Z");
    RDFGraph_addTriple(graph, " credential1 ", " VerificationMethod ", "did:example:123456789abcdefghi#key1");
    RDFGraph_addTriple(graph, " credential1 ", " ProofPurpose ", "assertionMethod");
    RDFGraph_addTriple(graph, " credential1 ", " jws ", "");

    RDFProcessor *processor = RDFProcessor_new(graph);
    RDFProcessor_process(processor, output);

    RDFProcessor_free(processor);
    RDFGraph_free(graph);
}

/* Global Variables ----------------------------------------------------------*/
cmox_ecc_handle_t Ecc_Ctx;           // ECC context
#define Working_Buffer_Size 2000
uint8_t Working_Buffer[Working_Buffer_Size];         // ECC working buffer
uint32_t Computed_Random[8];          // Random data buffer

UART_HandleTypeDef huart2;            // UART handle for USART2
CRC_HandleTypeDef hcrc;               // CRC handle

/* External Variables --------------------------------------------------------*/
extern UART_HandleTypeDef huart2;     // Assume UART2 is being used

/* Private Function Prototypes -----------------------------------------------*/
static void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_CRC_Init(void);
void Error_Handler(void);
void UART_Print(const char *pString);
void ByteArrayToHexString(const uint8_t *pData, size_t length, char *pStr);
void Print_Computed_Signature(const uint8_t *pSignature, size_t length);
void Print_Computed_Keys(const uint8_t *data, size_t length);
void UART_PrintSignature(const uint8_t *data, size_t length);

/* Data Buffers --------------------------------------------------------------*/
//const uint8_t Message[] = {"This is a test message"};

//const uint8_t Private_Key[] = {
//    0x70, 0x83, 0x09, 0xa7, 0x44, 0x9e, 0x15, 0x6b, 0x0d, 0xb7, 0x0e, 0x5b, 0x52, 0xe6, 0x06, 0xc7,
//    0xe0, 0x94, 0xed, 0x67, 0x6c, 0xe8, 0x95, 0x3b, 0xf6, 0xc1, 0x47, 0x57, 0xc8, 0x26, 0xf5, 0x90
//};
//
//const uint8_t Public_Key[] = {
//    0x29, 0x57, 0x8c, 0x7a, 0xb6, 0xce, 0x0d, 0x11, 0x49, 0x3c, 0x95, 0xd5, 0xea, 0x05, 0xd2, 0x99,
//    0xd5, 0x36, 0x80, 0x1c, 0xa9, 0xcb, 0xd5, 0x0e, 0x99, 0x24, 0xe4, 0x3b, 0x73, 0x3b, 0x83, 0xab,
//    0x08, 0xc8, 0x04, 0x98, 0x79, 0xc6, 0x27, 0x8b, 0x22, 0x73, 0x34, 0x84, 0x74, 0x15, 0x85, 0x15,
//    0xac, 0xca, 0xa3, 0x83, 0x44, 0x10, 0x6e, 0xf9, 0x68, 0x03, 0xc5, 0xa0, 0x5a, 0xdc, 0x48, 0x00
//};

const uint8_t Known_Random[] = {
    0x58, 0xf7, 0x41, 0x77, 0x16, 0x20, 0xbd, 0xc4, 0x28, 0xe9, 0x1a, 0x32, 0xd8, 0x6d, 0x23, 0x08,
    0x73, 0xe9, 0x14, 0x03, 0x36, 0xfc, 0xfb, 0x1e, 0x12, 0x28, 0x92, 0xee, 0x1d, 0x50, 0x1b, 0xdb
};

const uint8_t Known_Signature[] = {
    0x4a, 0x19, 0x27, 0x44, 0x29, 0xe4, 0x05, 0x22, 0x23, 0x4b, 0x87, 0x85, 0xdc, 0x25, 0xfc, 0x52,
    0x4f, 0x17, 0x9d, 0xcc, 0x95, 0xff, 0x09, 0xb3, 0xc9, 0x77, 0x0f, 0xc7, 0x1f, 0x54, 0xca, 0x0d,
    0x58, 0x98, 0x2b, 0x79, 0xa6, 0x5b, 0x73, 0x20, 0xf5, 0xb9, 0x2d, 0x13, 0xbd, 0xae, 0xcd, 0xd1,
    0x25, 0x9e, 0x76, 0x0f, 0x0f, 0x71, 0x8b, 0xa9, 0x33, 0xfd, 0x09, 0x8f, 0x6f, 0x75, 0xd4, 0xb7
};

uint8_t Computed_Hash[CMOX_SHA224_SIZE];                 // Computed hash buffer
uint8_t Computed_Signature[CMOX_ECC_SECP256R1_SIG_LEN];  // Computed signature buffer

/* Functions Definition ------------------------------------------------------*/

int main(void)
{
    cmox_hash_retval_t hretval;
    cmox_ecc_retval_t retval;
    size_t computed_size;
    uint32_t fault_check = CMOX_ECC_AUTH_FAIL;

    HAL_Init();               // STM32 HAL initialization
    SystemClock_Config();      // System clock configuration
    MX_GPIO_Init();            // GPIO initialization
    MX_USART2_UART_Init();     // UART initialization
    MX_CRC_Init();             // CRC initialization

    const cmox_ecc_impl_t curveParams = CMOX_ECC_SECP256R1_HIGHMEM;

    UART_Print("\r\n");
    UART_Print("Starting ECDSA key generation...\r\n");

    char Message[MAX_MESSAGE_SIZE] = {0};
    // Call the RDF processing function and pass the Message variable
    processRDF(Message);

    uint8_t privKey[32];
    size_t privKeyLen = sizeof(privKey);
    uint8_t pubKey[64];
    size_t pubKeyLen = sizeof(pubKey);

    cmox_ecc_construct(&Ecc_Ctx, CMOX_MATH_FUNCS_FAST, Working_Buffer, Working_Buffer_Size);

    retval = cmox_ecdsa_keyGen(&Ecc_Ctx, curveParams, Known_Random, sizeof(Known_Random), privKey, &privKeyLen, pubKey, &pubKeyLen);
    if (retval != CMOX_ECC_SUCCESS) {
        UART_Print("Key generation failed");
        return -1;
    }

    UART_Print("Private key: ");
    Print_Computed_Keys(privKey, privKeyLen);
    UART_Print("\r\n");

    UART_Print("Public key: ");
    Print_Computed_Keys(pubKey, pubKeyLen);
    UART_Print("\r\n");

    // Compute the SHA-224 digest
    hretval = cmox_hash_compute(CMOX_SHA224_ALGO,
                                Message, sizeof(Message),
                                Computed_Hash, CMOX_SHA224_SIZE,
                                &computed_size);

    // Check if hash computation was successful
    if (hretval != CMOX_HASH_SUCCESS || computed_size != CMOX_SHA224_SIZE)
    {
        UART_Print("Hash computation failed.\r\n");
        Error_Handler();
    }


    // Construct ECC context
    cmox_ecc_construct(&Ecc_Ctx, CMOX_ECC256_MATH_FUNCS, Working_Buffer, sizeof(Working_Buffer));

    // Compute the ECDSA signature
    retval = cmox_ecdsa_sign(&Ecc_Ctx,
                             CMOX_ECC_CURVE_SECP256R1,
                             Known_Random, sizeof(Known_Random),
							 privKey, sizeof(privKey),
                             Computed_Hash, CMOX_SHA224_SIZE,
                             Computed_Signature, &computed_size);

    // Verify the signature computation
    if (retval != CMOX_ECC_SUCCESS || computed_size != sizeof(Known_Signature))
    {
        UART_Print("Signature computation failed.\r\n");
        Print_Computed_Signature(Computed_Signature, computed_size);
        Error_Handler();
    }

    UART_Print("Signature computed successfully.\r\n");

    UART_Print("Computed Signature: ");
    UART_PrintSignature(Computed_Signature, computed_size);
    //Print_Computed_Signature(Computed_Signature, computed_size);
    UART_Print("\r\n");

    cmox_ecc_cleanup(&Ecc_Ctx);  // Clean up ECC context

    cmox_ecc_construct(&Ecc_Ctx, CMOX_ECC256_MATH_FUNCS, Working_Buffer, sizeof(Working_Buffer));
    retval = cmox_ecdsa_verify(&Ecc_Ctx,                                  /* ECC context */
                               CMOX_ECC_CURVE_SECP256R1,                  /* SECP256R1 ECC curve selected */
							   pubKey, sizeof(pubKey),            /* Public key for verification */
                               Computed_Hash, CMOX_SHA224_SIZE,           /* Digest to verify */
							   Computed_Signature, sizeof(Computed_Signature),  /* Data buffer to receive signature */
                               &fault_check);                             /* Fault check variable:*/

    // Check if the verification succeeded
    if (retval != CMOX_ECC_AUTH_SUCCESS || fault_check != CMOX_ECC_AUTH_SUCCESS)
    {
        UART_Print("Signature verification failed.\r\n");
        Error_Handler();
    }
    else
    {
        UART_Print("Signature verification successful!\r\n");
    }

    processRDF(Message);

    // Print the Message variable
    UART_Print(Message);
    saveRDF(Message);


    /* Cleanup context */
    cmox_ecc_cleanup(&Ecc_Ctx);


    while (1) {
        // Infinite loop
    }
}

/**
  * @brief Convert byte array to hex string
  */
void ByteArrayToHexString(const uint8_t *pData, size_t length, char *pStr)
{
    const char hexDigits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < length; ++i)
    {
        pStr[i * 2]     = hexDigits[(pData[i] >> 4) & 0x0F];
        pStr[i * 2 + 1] = hexDigits[pData[i] & 0x0F];
    }
    pStr[length * 2] = '\0'; // Null-terminate the string
}

void UART_PrintSignature(const uint8_t *data, size_t length) {
    size_t offset = 0;
    for (size_t i = 0; i < length; i++) {
        if ((offset + 3) < hexSignature) {
            offset += sprintf(&hexSignature[offset], "%02X", data[i]);
        } else {
            UART_Print("Error: hexSignature buffer overflow\r\n");
            return;
        }
    }
    hexSignature[offset] = '\0';
    UART_Print(hexSignature);
    UART_Print("\r\n");
}

/**
  * @brief Print computed ECDSA signature as hex
  */
void Print_Computed_Signature(const uint8_t *pSignature, size_t length)
{
    char signatureHex[2 * length + 1];
    ByteArrayToHexString(pSignature, length, signatureHex);
    UART_Print(signatureHex);
}

void Print_Computed_Keys(const uint8_t *data, size_t length)
{
    char keysHex[2 * length + 1];
    ByteArrayToHexString(data, length, keysHex);
    UART_Print(keysHex);
}

/**
  * @brief Print string over UART
  */
void UART_Print(const char *pString)
{
    HAL_StatusTypeDef status;
    status = HAL_UART_Transmit(&huart2, (uint8_t *)pString, strlen(pString), HAL_MAX_DELAY);

    // Check if transmission was successful
    if (status != HAL_OK)
    {
        Error_Handler();
    }
}

/**
  * @brief System Clock Configuration
  */
static void SystemClock_Config(void)
{
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE2);

    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState = RCC_HSI_ON;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
    {
        Error_Handler();
    }

    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK |
                                  RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
    {
        Error_Handler();
    }
}

/**
  * @brief CRC Initialization
  */
static void MX_CRC_Init(void)
{
    hcrc.Instance = CRC;
    if (HAL_CRC_Init(&hcrc) != HAL_OK)
    {
        Error_Handler();
    }
}

/**
  * @brief USART2 Initialization Function
  */
static void MX_USART2_UART_Init(void)
{
    huart2.Instance = USART2;
    huart2.Init.BaudRate = 115200;
    huart2.Init.WordLength = UART_WORDLENGTH_8B;
    huart2.Init.StopBits = UART_STOPBITS_1;
    huart2.Init.Parity = UART_PARITY_NONE;
    huart2.Init.Mode = UART_MODE_TX_RX;
    huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart2.Init.OverSampling = UART_OVERSAMPLING_16;
    if (HAL_UART_Init(&huart2) != HAL_OK)
    {
        Error_Handler();
    }
}

/**
  * @brief GPIO Initialization Function
  */
static void MX_GPIO_Init(void)
{
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    __HAL_RCC_GPIOA_CLK_ENABLE();

    GPIO_InitStruct.Pin = GPIO_PIN_2 | GPIO_PIN_3; // TX, RX
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    GPIO_InitStruct.Alternate = GPIO_AF7_USART2;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
}

/**
  * @brief Error Handler function
  */
void Error_Handler(void)
{
    __disable_irq();
    while (1) {
        // Loop indefinitely
    }
}
