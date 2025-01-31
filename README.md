# Credential_Signing-STM32

# STM32 Nucleo-F401RE CryptoLib Repository

## Setup Instructions

To set up the project and run the cryptographic programs, please follow these steps:

1. **Clone the Repository:**
   ```sh
   git clone https://github.com/yourusername/stm32-nucleo-crypto.git
   cd stm32-nucleo-crypto
   ```

2. **Install the Required Tools:**
   Ensure you have the following tools installed:
   - STM32CubeIDE or another compatible IDE
   - STM32CubeMX

3. **Open the Project:**
   - Launch STM32CubeIDE.
   - Open the project by selecting `File` -> `Open Projects from File System...` and navigating to the cloned repository directory.
   - Add the CryptoLib library to the project. 

4. **Configure Peripherals:**
   - Open the `.ioc` file in STM32CubeMX.
   - Enable CRC (Cyclic Redundancy Check).
   - Enable UART2 for serial communication.
   - Enable `Activate Clock Source` & `Activate Calenter` in RTC

5. **Generate Code:**
   - After configuring the peripherals, click on `Project` -> `Generate Code` to generate the necessary code for your STM32 project.
   - Note: If you have already created the project without activating CRC or UART, you have to copy and paste the main.c code after the generation of new code for CRC and UART.

6. **Build and Flash:**
   - Build the project in STM32CubeIDE.
   - Flash the program to your STM32 Nucleo-F401RE board.

7. **Run the Programs:**
   - Connect to the UART2 interface using a terminal program (e.g., PuTTY or Teraterm) to interact with the programs.
   - Follow the on-screen instructions to run and test the cryptographic functions.
