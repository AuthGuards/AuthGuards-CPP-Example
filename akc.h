#pragma once
#ifdef _KERNEL_MODE
namespace std
{
	template <class _Ty>
	struct remove_reference {
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_reference<_Ty&> {
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_reference<_Ty&&> {
		using type = _Ty;
	};

	template <class _Ty>
	using remove_reference_t = typename remove_reference<_Ty>::type;
	template <class _Ty>
	struct remove_const {
		using type = _Ty;
	};
	template <class _Ty>
	struct remove_const<const _Ty> {
		using type = _Ty;
	};
	template <class _Ty>
	using remove_const_t = typename remove_const<_Ty>::type;
}
#else
#include <type_traits>
#include <string>
#include <iostream>
#include <filesystem>
#include <iomanip>
#include <ctime>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif
#endif

#ifndef _KERNEL_MODE
#ifdef _WIN32

inline const char* akc_to_lpcstr(const std::string& s) { return s.c_str(); }
inline const char* akc_to_lpcstr(const char* s) { return s; }

inline void akc_secure_clear(std::string& s)
{
	if (!s.empty())
	{
#if defined(_WIN32) && !defined(_KERNEL_MODE)
		SecureZeroMemory(&s[0], s.size());
#else
		volatile char* v = &s[0];
		for (size_t i = 0; i < s.size(); ++i) v[i] = 0;
#endif
		s.clear();
	}
}

inline void akc_secure_clear(void* p, size_t n)
{
	if (p && n)
	{
#if defined(_WIN32) && !defined(_KERNEL_MODE)
		SecureZeroMemory(p, n);
#else
		volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
		for (size_t i = 0; i < n; ++i) v[i] = 0;
#endif
	}
}

inline bool akc_lock_string_in_memory(std::string& s)
{
#if defined(_WIN32) && !defined(_KERNEL_MODE)
	return s.empty() || (VirtualLock(&s[0], s.size()) != 0);
#else
	(void)s;
	return true;
#endif
}

inline void akc_unlock_string_from_memory(std::string& s)
{
#if defined(_WIN32) && !defined(_KERNEL_MODE)
	if (!s.empty())
		VirtualUnlock(&s[0], s.size());
#else
	(void)s;
#endif
}

#define HttpOpenRequestA(a,b,c,d,e,f,g,h) (::HttpOpenRequestA)(a, akc_to_lpcstr(b), c, d, e, f, g, h)
#define _dupenv_s(a,b,c) (::_dupenv_s)(a, b, akc_to_lpcstr(c))
#define bstr_t(x) _bstr_t(akc_to_lpcstr(x))
#define RegOpenKeyExA(a,b,c,d,e) (::RegOpenKeyExA)(a, akc_to_lpcstr(b), c, d, e)
#define RegQueryValueExA(a,b,c,d,e,f) (::RegQueryValueExA)(a, akc_to_lpcstr(b), c, d, e, f)

namespace std {
inline auto get_time(std::tm* tmb, const std::string& fmt) { return std::get_time(tmb, fmt.c_str()); }
}

#endif
#endif

namespace akc
{
	template<class _Ty>
	using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

	template <int _size, char _key1, char _key2, typename T>
	class skCrypter
	{
		static_assert(_size > 0, "skCrypter requires positive size");
	public:
		__forceinline constexpr skCrypter(T* data)
		{
			crypt(data);
		}

		__forceinline T* get()
		{
			return _storage;
		}

		__forceinline int size()
		{
			return _size;
		}

		__forceinline  char key()
		{
			return _key1;
		}

		__forceinline  T* encrypt()
		{
			if (!isEncrypted())
				crypt(_storage);

			return _storage;
		}

#ifndef _KERNEL_MODE
#ifdef _WIN32
		__forceinline std::string decrypt()
		{
			if (isEncrypted())
				crypt(_storage);
			std::string result(reinterpret_cast<const char*>(_storage), _size > 0 ? _size - 1 : 0);
			crypt(_storage);
			return result;
		}
#else
		__forceinline T* decrypt()
		{
			if (isEncrypted())
				crypt(_storage);
			return _storage;
		}
#endif
#else
		__forceinline T* decrypt()
		{
			if (isEncrypted())
				crypt(_storage);
			return _storage;
		}
#endif

		__forceinline bool isEncrypted()
		{
			return _size > 0 && _storage[_size - 1] != 0;
		}

		__forceinline void clear()
		{
			if (_size <= 0) return;
#if defined(_WIN32) && !defined(_KERNEL_MODE)
			SecureZeroMemory(_storage, static_cast<size_t>(_size) * sizeof(T));
#else
			volatile T* p = _storage;
			for (int i = 0; i < _size; i++)
				p[i] = 0;
#endif
		}

	private:
		__forceinline constexpr void crypt(T* data)
		{
			for (int i = 0; i < _size; i++)
			{
				_storage[i] = data[i] ^ (_key1 + i % (1 + _key2));
			}
		}

		T _storage[_size]{};
	};
}

#define AuthGuards(str) authguards_key(str, __TIME__[4], __TIME__[7])
#define authguards_key(str, key1, key2) []() { \
			constexpr static auto crypted = akc::skCrypter \
				<sizeof(str) / sizeof(str[0]), key1, key2, akc::clean_type<decltype(str[0])>>((akc::clean_type<decltype(str[0])>*)str); \
					return crypted; }() 
