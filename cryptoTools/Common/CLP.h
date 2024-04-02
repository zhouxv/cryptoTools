#pragma once

#include <unordered_map>
#include <set>
#include <list>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include "cryptoTools/Common/Defines.h"

namespace osuCrypto
{
    // An error that is thrown when the input isn't of the correct form.
    class CommandLineParserError : public std::exception
    {
    public:
        explicit CommandLineParserError(const char *message) : msg_(message) {}
        explicit CommandLineParserError(const std::string &message) : msg_(message) {}
        virtual ~CommandLineParserError() throw() {}
        virtual const char *what() const throw() { return msg_.c_str(); }

    protected:
        std::string msg_;
    };

    // Command Line Parser class.
    // Expecting the input to be of form
    //   -key_1 val_1 val_2 -key_2 val_3 val_4 ...
    // The values are optional but require a preceeding key denoted by -
    class CLP
    {
    public:
        // Default Constructor
        CLP() = default;

        // Parse the provided arguments.
        CLP(int argc, char **argv) { parse(argc, argv); }

        // Internal variable denoting the name of the program.
        std::string mProgramName;

        std::string mFullStr;

        // The key value store of the parsed arguments.
        std::unordered_map<std::string, std::list<std::string>> mKeyValues;

        // parse the command line arguments.
        // 解析命令行参数，将参数存储在 mKeyValues 中。程序名存储在 mProgramName 中，而完整的命令行参数字符串存储在 mFullStr 中
        void parse(int argc, char const *const *argv);

        // Set the default for the provided key. Keys do not include the leading `-`.
        // 设置指定键的默认值。如果键不存在或未设置值，则将值添加到键的值列表中；如果键已存在且已设置值，则将值添加到键的值列表中。
        void setDefault(std::string key, std::string value);

        // Set the default for the provided key. Keys do not include the leading `-`.
        // 设置一组键的默认值。如果这些键中至少有一个不存在或未设置值，则将默认值添加到第一个存在且未设置值的键。
        void setDefault(std::vector<std::string> keys, std::string value);

        // Set the default for the provided key. Keys do not include the leading `-`.
        void setDefault(std::string key, i64 value) { setDefault(key, std::to_string(value)); }

        // Set the default for the provided key. Keys do not include the leading `-`.
        void setDefault(std::vector<std::string> keys, i64 value) { setDefault(keys, std::to_string(value)); }

        // Manually set a flag.
        // 手动设置指定键的标志，用于表示该键存在但无关联值。
        void set(std::string name);

        // Return weather the key was provided on the command line or has a default.
        // 检查指定的键是否在命令行参数中设置
        bool isSet(std::string name) const;

        // Return weather the key was provided on the command line or has a default.
        // 检查指定的一组键是否至少有一个在命令行参数中设置
        bool isSet(std::vector<std::string> names) const;

        // Return weather the key was provided on the command line has an associated value or has a default.
        // 检查指定的键是否在命令行参数中设置，并且是否有关联值
        bool hasValue(std::string name) const;

        // Return weather the key was provided on the command line has an associated value or has a default.
        // 检查指定的一组键是否至少有一个在命令行参数中设置，并且是否有关联值
        bool hasValue(std::vector<std::string> names) const;

        // Return the first value associated with the key.
        // 返回与给定键 name 关联的第一个值。如果未找到值，则抛出 CommandLineParserError 异常。
        template <typename T>
        T get(const std::string &name) const
        {
            if (hasValue(name) == false)
                throw error(span<const std::string>(&name, 1));

            std::stringstream ss;
            ss << *mKeyValues.at(name).begin();

            T ret;
            ss >> ret;

            return ret;
        }

        // 返回与给定键 name 关联的第一个值，如果未找到键，则返回提供的 alternative 值。
        template <typename T>
        T getOr(const std::string &name, T alternative) const
        {
            if (hasValue(name))
                return get<T>(name);

            return alternative;
        }

        // 从给定的键名列表中查找第一个存在值的键，并返回其对应的值。如果所有的键都没有关联的值，则返回提供的默认值 alternative。
        template <typename T>
        T getOr(const std::vector<std::string> &name, T alternative) const
        {
            if (hasValue(name))
                return get<T>(name);

            return alternative;
        }

        // 使用错误消息构造一个 CommandLineParserError 对象，指示未为提供的标签名称设置任何值。
        CommandLineParserError error(span<const std::string> names) const
        {
            if (names.size() == 0)
                return CommandLineParserError("No tags provided.");
            else
            {
                std::stringstream ss;
                ss << "{ " << names[0];
                for (u64 i = 1; i < static_cast<u64>(names.size()); ++i)
                    ss << ", " << names[i];
                ss << " }";

                return CommandLineParserError("No values were set for tags " + ss.str());
            }
        }

        // Return the first value associated with the key.
        // 从给定的键名列表中查找第一个存在值的键，并返回其对应的值。
        // 如果所有的键都没有关联的值，则抛出一个 CommandLineParserError 异常，并使用 failMessage 参数提供的消息，如果提供了的话
        template <typename T>
        T get(const std::vector<std::string> &names, const std::string &failMessage = "") const
        {
            for (auto name : names)
                if (hasValue(name))
                    return get<T>(name);

            if (failMessage != "")
                std::cout << failMessage << std::endl;

            throw error(span<const std::string>(names.data(), names.size()));
        }

        // 从命令行参数中获取与给定键名 name 相关联的多个值，并返回一个 std::vector<T>。
        // 如果没有找到与键名相关联的值，则返回提供的备用值 alt。
        // 模板类型为整数类型时，返回值为 std::vector<T>.
        template <typename T>
        typename std::enable_if<std::is_integral<T>::value, std::vector<T>>::type
        getManyOr(const std::string &name, std::vector<T> alt) const
        {
            if (isSet(name))
            {
                auto &vs = mKeyValues.at(name);
                // if(vs.size())
                std::vector<T> ret;
                ret.reserve(vs.size());
                auto iter = vs.begin();
                T x;
                for (u64 i = 0; i < vs.size(); ++i)
                {
                    std::stringstream ss(*iter++);
                    ss >> x;
                    ret.push_back(x);
                    char d0 = 0, d1 = 0;
                    ss >> d0;
                    ss >> d1;
                    if (d0 == '.' && d1 == '.')
                    {
                        T end;
                        ss >> end;

                        T step = end > x ? 1 : -1;
                        x += step;
                        while (x < end)
                        {
                            ret.push_back(x);
                            x += step;
                        }
                    }
                }
                return ret;
            }
            return alt;
        }

        // Return the values associated with the key.
        // 如果没有找到与键名相关联的值，则返回提供的备用值 alt。
        // 非整数类型时
        template <typename T>
        typename std::enable_if<!std::is_integral<T>::value, std::vector<T>>::type
        getManyOr(const std::string &name, std::vector<T> alt) const
        {
            if (isSet(name))
            {
                auto &vs = mKeyValues.at(name);
                std::vector<T> ret(vs.size());
                auto iter = vs.begin();
                for (u64 i = 0; i < ret.size(); ++i)
                {
                    std::stringstream ss(*iter++);
                    ss >> ret[i];
                }
                return ret;
            }
            return alt;
        }

        // Return the values associated with the key.
        // 获取与给定键名 name 相关联的多个值，并返回一个 std::vector<T>。
        // 如果没有找到与键名相关联的值，则返回一个空的 std::vector<T>。
        template <typename T>
        std::vector<T> getMany(const std::string &name) const
        {
            return getManyOr<T>(name, {});
        }

        // Return the values associated with the key.
        // 接受一个键名列表，并依次检查每个键名，以尝试获取其相关联的值。
        // 如果找到任何一个键名有关联的值，则调用上面的 getMany 函数来获取这些值，并返回一个 std::vector<T>。
        // 如果所有的键名都没有关联的值，则返回一个空的 std::vector<T>。
        template <typename T>
        std::vector<T> getMany(const std::vector<std::string> &names) const
        {
            for (auto name : names)
                if (hasValue(name))
                    return getMany<T>(name);

            return {};
        }

        // Return the values associated with the key.
        // 接受一个键名列表，并依次检查每个键名，以尝试获取其相关联的值。
        // 如果找到任何一个键名有关联的值，则调用上面的 getMany 函数来获取这些值，并返回一个 std::vector<T>。
        // 如果所有的键名都没有关联的值，则抛出一个异常，并打印提供的错误消息。
        template <typename T>
        std::vector<T> getMany(const std::vector<std::string> &names, const std::string &failMessage) const
        {
            for (auto name : names)
                if (hasValue(name))
                    return getMany<T>(name);

            if (failMessage != "")
                std::cout << failMessage << std::endl;

            throw error(span<const std::string>(names.data(), names.size()));
        }

        const std::list<std::string> &getList(std::vector<std::string> names) const;
    };
}
