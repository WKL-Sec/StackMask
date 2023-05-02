# StackMask  

This is a PoC of encrypting the stack prior to custom sleeping by leveraging CPU cycles. This is the code of the relevant blog post: [Masking the Implant with Stack Encryption](https://whiteknightlabs.com/2023/05/02/masking-the-implant-with-stack-encryption/)

## Workflow  

Retrieve the RSP address to identify where the stack begins. Then use `VirtualQuery` to retrieve the range of the page of the virtual address space of the calling process, in order to calculate the end of the stack. Before encrypting, suspend the thread to avoid any abnormal behavior.

## Demo  

![stack_encryption_on_runtime](https://whiteknightlabs.com/wp-content/uploads/2023/05/Screenshot-from-2023-05-01-16-02-29.png)

## References  
The sleep mechanizm is taken from: https://shubakki.github.io/posts/2022/12/detecting-and-evading-sandboxing-through-time-based-evasion/

## Author  
Kleiton Kurti ([@kleiton0x00](https://github.com/kleiton0x00))
