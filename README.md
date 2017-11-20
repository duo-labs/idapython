# Duo Labs IDAPython Repository

This IDAPython repository contains a few Python modules developed for use with IDA Pro from the researchers at Duo Labs. There are currently two modules being released. These modules are discussed in the blog post at <duo.sc/personal-protection>, and in the associated paper [Examining Personal Protection Devices
Hardware & Firmware Research Methodology in Action](https://duo.com/assets/ebooks/Duo-Labs-Personal-Protection-Devices.pdf).

We also wish to thank two contributors that discussed ARM code detection heuristics during the development of this code: Luis Miras and Josh Mitchell. 

+ Cortex M Firmware (cortex_m_firmware.py) -- 
This Cortex M Firmware module grooms an IDA Pro database containing firmware from an ARM Cortex M microcontroller. This module will annotate the firmware vector table, which contains a number of function pointers. This vector table annotation will cause IDA Pro to perform auto analysis against the functions these pointers point to. The Cortex M Firmware module also calls into the Amnesia module to automate discovery of additional code in the firmware image using the Amnesia heuristics.

This example shows the most common usage of the code, for loading firmware images with the vector table located at address 0x0:
```python
from cortex_m_firmware import *
cortex = CortexMFirmware(auto=True)
```

This example shows how to annotate multiple vector tables in a firmware:
```python
from cortex_m_firmware import *
cortex = CortexMFirmware()
cortex.annotate_vector_table(0x4000)
cortex.annotate_vector_table(0x10000)
cortex.find_functions()
```

+ Amnesia (amnesia.py) -- 
Amnesia is an IDAPython module designed to use byte level heuristics to find ARM thumb instructions in undefined bytes in an IDA Pro database. Currently, the heuristics in this module find code in a few different ways. Some instructions identify and define new code by looking for comon byte sequences that correspond to particular ARM opcodes. Other functions in this module define new functions based on sequences of defined instructions.

```python
class Amnesia:
 def find_function_epilogue_bxlr(self, makecode=False)
 def find_pushpop_registers_thumb(self, makecode=False)
 def find_pushpop_registers_arm(self, makecode=False)
 def make_new_functions_heuristic_push_regs(self, makefunction=False)
 def nonfunction_first_instruction_heuristic(self, makefunction=False)
```