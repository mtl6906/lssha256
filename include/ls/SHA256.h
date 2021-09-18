#ifndef LS_SHA256_H
#define LS_SHA256_H

#include "string"
#include "vector"

#define IPAD_BASE_VALUE 0x36 
#define OPAD_BASE_VALUE 0x5c

namespace ls
{
	class SHA256
	{
		public:
			SHA256();
			std::string hash(const std::string &data);
			std::vector<uint8_t> hash(const std::vector<uint8_t> &data);
			std::string hmac(const std::string &data, const std::string &key);
		protected:
			std::vector<uint32_t> _hs;
			std::vector<uint32_t> _k;
	};
}

#endif
