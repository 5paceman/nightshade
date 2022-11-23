#pragma once

// https://guidedhacking.com/threads/compile-time-string-encryption.16608/

template<class Class>
using RawType = typename std::remove_const_t<std::remove_reference_t<Class>>;

#define SString_Key(String, Key) []() {\
                    constexpr static auto x = nightshade::StringEncrypt<sizeof(String) / sizeof(String[0]), Key, RawType<decltype(String[0])>>((RawType<decltype(String[0])>*)String);\
                    return x;}()
#define SString(String) SString_Key(String,__TIME__[0])



namespace nightshade {
	template<unsigned long StringSize, int key, typename Type>
	class StringEncrypt
	{
	public:
		constexpr StringEncrypt(Type* data)
		{
			EncryptString(data);
		}

		constexpr Type* decrypt()
		{
			Type TempBuffer[StringSize]{};
			for (int i = 0; i < StringSize; i++)
			{
				TempBuffer[i] = DataBuffer[i] ^ (key + i);
			}
			return TempBuffer;
		}
	private:
		constexpr void EncryptString(Type* data)
		{
			for (int i = 0; i < StringSize; i++)
			{
				DataBuffer[i] = data[i] ^ (key + i);
			}
		}

		Type DataBuffer[StringSize]{};
	};
}
