#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" char *rcsdate2str(const char *v);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string v = provider.ConsumeRandomLengthString(1000);

    rcsdate2str(v.c_str());

    return 0;
}
