local crypt = loadstring(game:HttpGet("https://raw.githubusercontent.com/rex-rbx/UselessModules/refs/heads/main/Cryptography.luau", true))()
local AEAD = crypt.Encryption.AEAD
local CSPRNG = crypt.Random.CSPRNG
local secretbox = {}
function secretbox.keyGen(): string
    return buffer.tostring(CSPRNG.RandomBytes(32))
end
function secretbox.seal(message: string, key: string, nonce: string?, rounds: number?, UseXChaCha20: boolean?, AAD: buffer?): string
    local keyBuf = buffer.fromstring(key)
    local nonceBuf = nonce and buffer.fromstring(nonce) or CSPRNG.RandomBytes(24)
    local msgBuf = buffer.fromstring(message)

    local ciphertext, tag = AEAD.Encrypt(
        msgBuf,
        keyBuf,
        nonceBuf,
        AAD or nil,
        rounds or nil,
        (UseXChaCha20 == nil and true) or UseXChaCha20
    )
    return buffer.tostring(nonceBuf)
        .. buffer.tostring(ciphertext)
        .. buffer.tostring(tag)
end
function secretbox.open(box: string, key: string, nonce: string?, rounds: number?, UseXChaCha20: boolean?, AAD: buffer?): string?
    local keyBuf = buffer.fromstring(key)
    local nonceBuf
    local cipherBuf
    local tagBuf
    if nonce then
        nonceBuf = buffer.fromstring(nonce)
        local boxBuf = buffer.fromstring(box)
        local total = buffer.len(boxBuf)
        tagBuf = buffer.create(16)
        buffer.copy(tagBuf, 0, boxBuf, total - 16, 16)
        cipherBuf = buffer.create(total - 16)
        buffer.copy(cipherBuf, 0, boxBuf, 0, total - 16)
    else
        local boxBuf = buffer.fromstring(box)
        local total = buffer.len(boxBuf)
        nonceBuf = buffer.create(24)
        buffer.copy(nonceBuf, 0, boxBuf, 0, 24)
        local cipherLen = total - 24 - 16
        cipherBuf = buffer.create(cipherLen)
        buffer.copy(cipherBuf, 0, boxBuf, 24, cipherLen)
        tagBuf = buffer.create(16)
        buffer.copy(tagBuf, 0, boxBuf, 24 + cipherLen, 16)
    end
    local plainBuf = AEAD.Decrypt(
        cipherBuf,
        keyBuf,
        nonceBuf,
        tagBuf,
        AAD or nil,
        rounds or nil,
        (UseXChaCha20 == nil and true) or UseXChaCha20
    )
    if not plainBuf then
        return nil
    end
    return buffer.tostring(plainBuf)
end
return secretbox
