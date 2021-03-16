## SIGGREGATOR ~ SIGnature agGREGATOR

Even if this project's name is one of the worst ever, Siggregator could be very useful.

In *malware analysis*, we often have to categorize many binary samples based on static signatures.

In my humble experience, I noticed that the best signatures are those of:

1. The evergreen [libmagic](https://man7.org/linux/man-pages/man3/libmagic.3.html) library

2. [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy)

3. [Yara](https://virustotal.github.io/yara/) signatures of [Retdec](https://github.com/avast/retdec/tree/master/support/yara_patterns/tools)

However, the approaches and use cases are totally different.
First of all, `libmagic` just recognizes file types based on magic numbers, so no packers, compilers, installers, protectors, etc.
Detect-It-Easy (DIE) uses finely tuned signatures bases on a dedicated scripting language (and therefore a dedicated engine), 
while Retdec provides well-maintained Yara signatures.
DIE is very accurate but slow, and its database lacks some rules, while Yara is very fast and has a vast database but prone to false positives.
Moreover, they use different technologies, which are sometimes tedious to configure on different operating systems.

Siggregator was born to be used as a [Docker](https://www.docker.com/) container à la build&run plug&play minimum-effort&maximum-result, 
to compare the output of the tools mentioned above.

```
git clone https://github.com/packmad/Siggregator.git
cd Siggregator
docker build . -t packmad:siggregator
./siggregator.sh IN_DIR OUT_FILE
```

* `IN_DIR` - is the input directory that contains the files to be analyzed
* `OUT_FILE` - will be a json file containing the output of those tools


