# eBPF-Research
###### Documenting eBPF under the context of AuroraHosts for learning and implementation purposes.



## What is eBPF?
First of all, eBPF stands for **e**xtended **B**erkeley **P**acket **F**ilter. Now onto a basic level, eBPF allows you to run code kernel-side. Typically programs are meant to be run in userspace, this is where 99% of programs run. Userspace programs then can interact with the machine via system calls to the kernel. eBPF programs on the other hand, run as part of the kernel. Because of this, they are much more restricted than userspace programs but are a lot more low level and much more efficient. 

eBPF programs must also pass a verifier check before they can begin execution, the [verifier](https://github.com/torvalds/linux/blob/9e9fb7655ed585da8f468e29221f0ba194a5f613/kernel/bpf/verifier.c) is a part of the kernel (it's about a 14000 line file) that makes sure eBPF programs are safe to run. It will commonly check for:
* Unbounded loops/While true loops
* Infinite looping/infinite recursion
* Invalid memory accesses (accessing memory beyond what's allocated to the program)
* Much much more, the verifier is an incredibly complex program.

There are ways the programmer can "make the verifier happy" so to speak. Those methods will be discussed later on. 

It's evident that eBPF is used in the networking sector (given its definition, Berkeley *packet* filter). Due to its nature in low level packet handling, its most common application is in DDoS mitigation. Companies like [Clouflare](https://www.cloudflare.com/), [Path.net](https://path.net/), [Corero](https://www.corero.com/) and many others benefit from eBPF technology to protect servers from attacks. Since eBPF runs very low on the network stack, an eBPF program can intercept malicious packets long before they are able to take up server resources, thus mitigating the damage that would've been done by that packet. 



## How can we benefit from eBPF?

We can use eBPF to mitigate attacks against our own servers. This would be done through one of eBPF's program types, XDP. E**X**press **D**ata **P**ath (XDP) is simple and easy to use when it comes to packet handling and mitigation. An XDP program would run on a network interface and run itself on each incoming packet to that interface. The program would look for abnormalities in packets to drop those packets. 

We can specifically benefit from XDP with application filters. Application filters are commonly XDP programs that are built around a specific application. An 'application' in this case just represents any targeted program that would be running on a server, it can be a game, a database, a website or anything else. The goal of these application filters are to only pass through legitimate traffic while preventing all other traffic. This kind of filtering has proven to be more effective than general purpose filtering but can only protect against a single type of service. Companies like Path.net are renown for their application filtering. 

### An example of how an application filter can work

Let's say we're trying to protect a FiveM server from DDoS attacks. Now FiveM runs on port 30120 by default so we already know that 30120 will be the port used for filtering in our application filter. Next we know that FiveM runs on both the TCP and UDP protocols so we can allow those 2 while blocking all other IP based protocols. This is just the basic information, however when working on application filtering there are much more nuanced quirks to an application. For example we would also need to look into the following:

* How the application uses it's protocols (I.e, FiveM uses UDP for in-game data and TCP for initializing connections and downloading server resources).
* How each packet is formed and structured.
* Looking into if the application uses other application layer protocols (such as HTTP) and filtering those as necessary.
* Rate limiting based on the application.

There are also more general purpose filtering methods that can filter generic attacks that aren't necessarily attacking a service such as:

* Port punching, closing all ports except for the ones in use. 
* Checking for malformed packets at each layer (Ethernet layer, IP layer, TCP, UDP, etc).

 

## The basics of eBPF and XDP programming

eBPF programming is drastically different than traditional programming due to it's hard restrictions on the use of external functions. Firstly, eBPF programming is not limited to any language, since at a basic level, you're just making syscalls to the kernel. Meaning that you can effectively develop eBPF programs in almost any language, given that there is support for making syscalls. However there are 4 languages in particular that are most widely used in eBPF development. Those languages are:

* C (The most supported language, has helper libraries like [libbpf](https://github.com/libbpf/libbpf) and [xdp-tools](https://www.youtube.com/watch?v=C7wPLB0l97k))
* Go (With the help of [Go eBPF](https://github.com/dropbox/goebpf))
* Rust (With the help of [RedBPF](https://github.com/foniod/redbpf))
* Python (This is not a standalone eBPF development language, it's paired with C through the use of [bcc](https://github.com/iovisor/bcc))

While there are a growing number of eBPF supported languages, C is still the most widely used and supported language. All of the other libraries have their own limitations and missing support in some areas of eBPF. 

Now onto the workings of XDP programs in C. An XDP program in C will always start with a single function, this function is what gets executed every time a packet is received, this is also where our mitigations methods would take place. This function also takes in a single parameter, that being the [xdp_md struct](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#:~:text=struct%20xdp_md%20%7B,%7D%3B) (link to the definition included). There are 2 variables in particular for now, the **data** and **data_end** variables. While these two variables are defined with type __u32 (unsigned 32 bit integer), they are actually pointers in disguise that need to be casted to void pointers. The data variable is a pointer to the first byte in the packet while the data_end variable is a pointer to the last byte in the packet. In other words, the packet data lies between these two pointers. 

There are other variables as part of the xdp_md struct however they are not needed for the basic implementation of an XDP filter.



## Writing a basic XDP program

Writing XDP programs, or eBPF programs in general are a bit different from traditional programs code-wise. As mentioned before they are run from a single function which is executed through every packet. The following is a very basic example of an XDP filter.

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_pass")
int pass_filter(struct *xdp_md ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

1. The first bpf.h include is necessary for all BPF programs as it defines many important structs and methods for BPF programs.

2. As the name implies, the bpf_helpers header contains many helpers for BPF programs, they wrap many of the BPF syscalls into easy-to-use functions. In this example we're only using the "SEC" macro from this header, it defines ELF sections for the compiler. 

3. Next we have the main function called pass_filter, it gets defined under the "xdp_pass" section and takes in an xdp_md struct pointer called ctx. This represents the context of the packet we're passing in.

4. In the function pass_filter, we only return XDP_PASS. This is one of a few actions or return codes in XDP. XDP_PASS just means that we should let the current packet (as passed in by the ctx pointer) pass up the network stack. There are a few more XDP actions such as:

   * XDP_DROP
   * XDP_TX
   * XDP_ABORTED
   * XDP_REDIRECT

   DROP and PASS are the most widely used in XDP filtering. DROP is the counterpart to PASS, it just means to drop the packet and do not let it continue up the network stack.

5. Finally we define a license section, using the GPL license. This is often necessary as the kernel will not let you load an eBPF program that uses GPL licensed functions without having a GPL license on your program. 

> Note: All XDP sample programs can be found in the samples folder included in the repo.

