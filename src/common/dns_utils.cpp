/*
 *    Copyright (c) 2021, The OpenThread Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

#include "common/dns_utils.hpp"

#include <algorithm>
#include <assert.h>

#include "common/code_utils.hpp"

static bool NameEndsWithDot(const std::string &aName)
{
    return !aName.empty() && aName.back() == '.';
}

DnsNameInfo SplitFullDnsName(const std::string &aName)
{
    size_t      transportPos;
    DnsNameInfo nameInfo;
    std::string fullName = aName;

    if (!NameEndsWithDot(fullName))
    {
        fullName += '.';
    }

    transportPos = fullName.rfind("._udp");

    if (transportPos == std::string::npos)
    {
        transportPos = fullName.rfind("._tcp");
    }

    if (transportPos == std::string::npos)
    {
        // host.domain or domain
        size_t dotPos = fullName.find_first_of('.');

        assert(dotPos != std::string::npos);

        // host.domain
        nameInfo.mHostName = fullName.substr(0, dotPos);
        nameInfo.mDomain   = fullName.substr(dotPos + 1, fullName.length() - dotPos - 1);
    }
    else
    {
        // service or service instance
        size_t dotPos = transportPos > 0 ? fullName.find_last_of('.', transportPos - 1) : std::string::npos;

        size_t domainPos = fullName.find_first_of('.', transportPos + 1);

        nameInfo.mDomain = fullName.substr(domainPos + 1);

        // subtypes beginning (if any present)
        size_t commaPos = fullName.find_first_of(",");

        if (commaPos != std::string::npos)
        {
            SplitSubtypes(fullName.substr(commaPos, domainPos - commaPos), nameInfo.mSubtypes);
        }

        if (dotPos == std::string::npos)
        {
            // service.domain
            nameInfo.mServiceName = fullName.substr(0, transportPos + 5);
        }
        else
        {
            // instance.service.domain
            nameInfo.mInstanceName = fullName.substr(0, dotPos);
            nameInfo.mServiceName  = fullName.substr(dotPos + 1, transportPos + 4 - dotPos);
        }
    }

    if (!NameEndsWithDot(nameInfo.mDomain))
    {
        nameInfo.mDomain += '.';
    }

    return nameInfo;
}

void SplitSubtypes(std::string aSubtypes, std::vector<std::string> &aSubtypesList)
{
    // TODO: add some max sub types number and verify it?
    size_t prevCommaPos = aSubtypes.find_first_of(',');
    for (int subtypesNumber = std::count(aSubtypes.begin(), aSubtypes.end(), ','); subtypesNumber > 0; subtypesNumber--)
    {
        size_t nextCommaPos = aSubtypes.find_first_of(',', prevCommaPos + 1);
        if (nextCommaPos == std::string::npos)
        {
            // This is the last subtype and it ends at the end of whole subtypes string.
            aSubtypesList.push_back(aSubtypes.substr(prevCommaPos + 1));
        }
        else
        {
            // The current subtype range ends on the next comma.
            aSubtypesList.push_back(aSubtypes.substr(prevCommaPos + 1, nextCommaPos - prevCommaPos - 1));
            prevCommaPos = nextCommaPos;
        }
    }
}

otbrError SplitFullServiceInstanceName(const std::string &       aFullName,
                                       std::string &             aInstanceName,
                                       std::string &             aType,
                                       std::vector<std::string> &aSubtypes,
                                       std::string &             aDomain)
{
    otbrError   error    = OTBR_ERROR_NONE;
    DnsNameInfo nameInfo = SplitFullDnsName(aFullName);

    VerifyOrExit(nameInfo.IsServiceInstance(), error = OTBR_ERROR_INVALID_ARGS);

    aInstanceName = std::move(nameInfo.mInstanceName);
    aType         = std::move(nameInfo.mServiceName);
    aSubtypes     = std::move(nameInfo.mSubtypes);
    aDomain       = std::move(nameInfo.mDomain);

exit:
    return error;
}

otbrError SplitFullServiceName(const std::string &aFullName, std::string &aType, std::string &aDomain)
{
    otbrError   error    = OTBR_ERROR_NONE;
    DnsNameInfo nameInfo = SplitFullDnsName(aFullName);

    VerifyOrExit(nameInfo.IsService(), error = OTBR_ERROR_INVALID_ARGS);

    aType   = std::move(nameInfo.mServiceName);
    aDomain = std::move(nameInfo.mDomain);

exit:
    return error;
}

otbrError SplitFullHostName(const std::string &aFullName, std::string &aHostName, std::string &aDomain)
{
    otbrError   error    = OTBR_ERROR_NONE;
    DnsNameInfo nameInfo = SplitFullDnsName(aFullName);

    VerifyOrExit(nameInfo.IsHost(), error = OTBR_ERROR_INVALID_ARGS);

    aHostName = std::move(nameInfo.mHostName);
    aDomain   = std::move(nameInfo.mDomain);

exit:
    return error;
}
