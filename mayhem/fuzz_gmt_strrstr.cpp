#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
    #include "gmt_common_string.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string a = provider.ConsumeRandomLengthString();
    std::string b = provider.ConsumeRandomLengthString();

    gmt_strrstr(a.c_str(), b.c_str());

    return 0;
}
