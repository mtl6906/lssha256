#include "ls/SHA256.h"
#include "cstring"
#include "cstdio"

using namespace std;

namespace ls
{
//	right rotate
	uint32_t rr(uint32_t data, int bit)
	{
		int mask = (1 << bit) - 1;
		int right = data & mask;
		data >>= bit;
		return data | (right << (32 - bit));
	}
//	right shift
	uint32_t rs(uint32_t data, int bit)
	{
		return data >> bit;
	}
	
	string hextoString(uint32_t data)
	{
		string result(8, '\0');
		snprintf((char *)result.c_str(), result.size() + 1, "%08x", data);
		return result;
	}

//	split the string to 512 bit chunk, the last chunk may be not full
	vector<vector<uint8_t>> split(const vector<uint8_t> &data)
	{
		auto it = data.begin();
		int chunkNum = data.size() / 64;
		int lastNum = data.size() % 64;
		vector<vector<uint8_t>> chunks(chunkNum + (lastNum == 0 ? 0 : 1));
		for(int i=0;i<chunkNum;++i)
		{
			vector<uint8_t> chunk(64);
			for(int j=0;j<64;++j)
			{
				chunk[j] = *it;
				++it;
			}
			chunks[i] = std::move(chunk);
		}
		if(lastNum > 0)
		{
			vector<uint8_t> chunk(lastNum);
			for(int i=0;i<lastNum;++i)
			{
				chunk[i] = *it;
				++it;
			}
			*chunks.rbegin() = std::move(chunk);
		}
		return chunks;
	}
//	fill length into chunk
	void fillLength(vector<uint8_t> &chunk, uint64_t len)
	{
		for(int i=7;i>=0;--i)
			chunk.push_back((len >> i*8) & 0xff);
	}
//	padding the chunk with 0x80 and 0x0
	void padding(vector<vector<uint8_t>> &chunks)
	{
		auto lastChunk = chunks.rbegin();
		int mod = lastChunk -> size();
		uint64_t len = (lastChunk -> size() + ((chunks.size() - 1) << 6)) << 3;
		if(mod != 64)
			lastChunk -> push_back(0x80);
		if(mod >= 56)
		{
			for(int i=lastChunk -> size();i<64;++i)
				lastChunk -> push_back(0);
			chunks.emplace_back();
			lastChunk = chunks.rbegin();
		}
		if(mod == 64)
			lastChunk -> push_back(0x80);
		while(lastChunk -> size()  < 56)
			lastChunk -> push_back(0);	
		fillLength(chunks[chunks.size()-1], len);
	}

	void fill(vector<uint8_t> &chunk, vector<uint32_t> &w)
	{
	//	copy chunk to w's first 16 elements
		for(int i=0;i<16;++i)
			for(int j=3;j>=0;--j)
				w[i] |= chunk[i*4 + 3-j] << (j * 8);
	//	calculate the next 48 elements of w from the first 16
		for(int j=16;j<64;++j)
		{
			int a = w[j-15];
			int b = w[j-2];
			int s0 = rr(a, 7) ^ rr(a, 18) ^ rs(a, 3);
			int s1 = rr(b, 17) ^ rr(b, 19) ^ rs(b, 10);
			w[j] = w[j-16] + s0 + w[j-7] + s1;
		}
	}

	void compress(vector<uint32_t> &hs, vector<uint32_t> &k, vector<uint32_t> &w)
	{
		int a = hs[0], b = hs[1], c = hs[2], d = hs[3],
		e = hs[4], f = hs[5], g = hs[6], h = hs[7];
		for(int j=0;j<64;++j)
		{
			int s1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
			int ch = (e & f) ^ ((~e) & g);
			int tmp1 = h + s1 + ch + k[j] + w[j];
			int s0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
			int maj = (a & b) ^ (a & c) ^ (b & c);
			int tmp2 = s0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + tmp1;
			d = c;
			c = b;
			b = a;
			a = tmp1 + tmp2;
		}
		hs[0] += a;
		hs[1] += b;
		hs[2] += c;
		hs[3] += d;
		hs[4] += e;
		hs[5] += f;
		hs[6] += g;
		hs[7] += h;
	}
	
	SHA256::SHA256() : 
	//	first 8 prime's square root
		_hs({0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}), 
	//	first 64 prime's cube root
		_k({0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2})
	{
		
	}

	vector<uint8_t> split(const vector<uint32_t> &data)
	{
		vector<uint8_t> result(32);
		for(int i=0;i<8;++i)
		{
			result[i*4] = (data[i] & 0xff000000) >> 24;
			result[i*4+1] = (data[i] & 0x00ff0000) >> 16;
			result[i*4+2] = (data[i] & 0x0000ff00) >> 8;
			result[i*4+3] = data[i] & 0x000000ff;
		}
		return result;
	}

	vector<uint8_t> SHA256::hash(const vector<uint8_t> &data)
	{
		vector<uint32_t> hs = _hs;
		vector<uint32_t> k = _k;
		auto chunks = split(data);
		padding(chunks);
		for(auto &chunk : chunks)
		{
			vector<uint32_t> w(64);
			fill(chunk, w);
			compress(hs, k, w);
		}
		return split(hs);
	}

	vector<uint8_t> split(const string &str)
	{
		vector<uint8_t> data(str.size() / 2);
		for(int i=0;i<data.size();++i)
			data.emplace_back(stoi(str.substr(i*2, 2), nullptr, 16));
		return data;
	}

	string to_string(const vector<uint8_t> &data)
	{
		string result(64, '\0');
		for(int i=0;i<32;++i)
			snprintf((char *)result.c_str() + 2*i, result.size() - i*2 + 1, "%02x", data[i]);
		return result;
	}

	string SHA256::hash(const string &str)
	{
		vector<uint8_t> data(str.size());
		memcpy(data.data(), str.c_str(), data.size() * sizeof(data[0]));
		vector<uint8_t> tmp = hash(data);	
		return to_string(tmp);
	}

	string SHA256::hmac(const string &data, const string &key)
	{
		vector<uint8_t> _key(64, '\0');
		if(key.size() > 64)
			memcpy(_key.data(), (char *)hash(key).c_str(), _key.size() * _key[0]);
		else
			memcpy(_key.data(), (char *)key.c_str(), key.size() * sizeof(key[0]));
		vector<uint8_t> ipad(_key.size() + data.size(), IPAD_BASE_VALUE);
		for(int i=0;i<_key.size();++i)
			ipad[i] ^= _key[i];
		memcpy(ipad.data() + _key.size(), (char *)data.c_str(), data.size() * sizeof(data[0]));
		vector<uint8_t> result = hash(ipad);
		vector<uint8_t> opad(_key.size() + result.size(), OPAD_BASE_VALUE);
		for(int i=0;i<_key.size();++i)
			opad[i] ^= _key[i];
		memcpy(opad.data() + _key.size(), result.data(), result.size() * sizeof(result[0]));
		return to_string(hash(opad));
	}
}

