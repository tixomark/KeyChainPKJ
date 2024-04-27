// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import Security

/// Управление хранилищем ключей в Keychain.
public final class KeyChain {
    /// Получает значение по ключу из Keychain.
    /// - Parameter key: Ключ для поиска значения.
    /// - Returns: Значение, ассоциированное с ключом, или `nil`, если значение не найдено.
    public static func getValue(forKey key: String) -> String? {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: key,
            kSecReturnAttributes: true,
            kSecReturnData: true
        ] as CFDictionary
        var ref: AnyObject?
        SecItemCopyMatching(query, &ref)
        guard let result = ref as? NSDictionary,
              let data = (result[kSecValueData] as? Data)
        else { return nil }
        return String(decoding: data, as: UTF8.self)
    }
    
    /// Сохраняет значение в Keychain под указанным ключом.
    /// - Parameters:
    ///   - value: Значение для сохранения.
    ///   - key: Ключ, по которому будет сохранено значение.
    /// - Returns: `true`, если сохранение прошло успешно, иначе `false`.
    @discardableResult
    static public func save(_ value: String, forKey key: String) -> Bool {
        let attributes = [
            kSecValueData: value.data(using: .utf8)!,
            kSecAttrAccount: key,
            kSecClass: kSecClassGenericPassword
        ] as CFDictionary
        let status = SecItemAdd(attributes, nil)
        return status == errSecSuccess
    }
    
    /// Обновляет значение в Keychain для указанного ключа.
    /// - Parameters:
    ///   - value: Новое значение.
    ///   - key: Ключ, для которого обновляется значение.
    /// - Returns: `true`, если обновление прошло успешно, иначе `false`.
    @discardableResult
    static public func update(_ value: String, forKey key: String) -> Bool {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: key,
        ] as CFDictionary
        let attributes = [
            kSecValueData: value.data(using: .utf8)!,
            kSecAttrAccount: key,
        ] as CFDictionary
        let status = SecItemUpdate(query, attributes)
        return status == errSecSuccess
    }
    
    /// Удаляет значение из Keychain по указанному ключу.
    /// - Parameter key: Ключ, для которого удаляется значение.
    /// - Returns: `true`, если удаление прошло успешно, иначе `false`.
    @discardableResult
    static public func deleteValue(forKey key: String) -> Bool {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: key,
        ] as CFDictionary
        let status = SecItemDelete(query)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
