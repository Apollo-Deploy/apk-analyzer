//! Certificate Parser for APK Signing Information
//!
//! Parses PKCS#7 signature files (.RSA, .DSA, .EC) from APK META-INF directory
//! and extracts X.509 certificate information including:
//! - Subject and issuer distinguished names
//! - Validity dates (notBefore, notAfter)
//! - MD5 and SHA-256 fingerprints
//! - Signature algorithm name
//!
//! ## PKCS#7 Structure (SignedData)
//!
//! The APK signing files contain PKCS#7 SignedData structures:
//! ```
//! ContentInfo ::= SEQUENCE {
//!     contentType ContentType,
//!     content [0] EXPLICIT ANY DEFINED BY contentType
//! }
//!
//! SignedData ::= SEQUENCE {
//!     version CMSVersion,
//!     digestAlgorithms DigestAlgorithmIdentifiers,
//!     encapContentInfo EncapsulatedContentInfo,
//!     certificates [0] IMPLICIT CertificateSet OPTIONAL,
//!     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//!     signerInfos SignerInfos
//! }
//! ```
//!
//! ## Usage
//!
//! ```zig
//! const cert = @import("certificate.zig");
//!
//! // Parse a PKCS#7 signature file
//! var parser = cert.CertificateParser.init(allocator);
//! defer parser.deinit();
//!
//! const info = try parser.parsePkcs7(signature_data);
//! std.debug.print("Subject: {s}\n", .{info.subject});
//! std.debug.print("Fingerprint SHA-256: {s}\n", .{info.fingerprint_sha256_hex});
//! ```

const std = @import("std");
const zip = @import("zip.zig");

/// Certificate parser for APK signing information
pub const CertificateParser = struct {
    allocator: std.mem.Allocator,

    pub const CertError = error{
        InvalidFormat,
        UnsupportedAlgorithm,
        TruncatedData,
        NoCertificateFound,
        OutOfMemory,
        InvalidAsn1,
        InvalidOid,
        InvalidUtcTime,
        InvalidGeneralizedTime,
    };

    /// Certificate information extracted from PKCS#7 signature
    pub const CertificateInfo = struct {
        /// Subject distinguished name (e.g., "CN=Developer, O=Company")
        subject: []const u8,
        /// Issuer distinguished name
        issuer: []const u8,
        /// Serial number as hex string
        serial_number: []const u8,
        /// Validity start time (Unix timestamp)
        not_before: i64,
        /// Validity end time (Unix timestamp)
        not_after: i64,
        /// MD5 fingerprint of the certificate (16 bytes)
        fingerprint_md5: [16]u8,
        /// SHA-256 fingerprint of the certificate (32 bytes)
        fingerprint_sha256: [32]u8,
        /// Signature algorithm name (e.g., "SHA256withRSA")
        signature_algorithm: []const u8,
        /// Public key algorithm (e.g., "RSA", "EC", "DSA")
        public_key_algorithm: []const u8,
        /// Public key size in bits
        public_key_size: u32,
        /// Raw certificate data (DER encoded)
        raw_certificate: []const u8,
        /// Allocator for cleanup
        allocator: std.mem.Allocator,

        pub fn deinit(self: *CertificateInfo) void {
            self.allocator.free(self.subject);
            self.allocator.free(self.issuer);
            self.allocator.free(self.serial_number);
            self.allocator.free(self.signature_algorithm);
            self.allocator.free(self.public_key_algorithm);
        }
    };

    // ASN.1 tag constants
    const ASN1_SEQUENCE: u8 = 0x30;
    const ASN1_SET: u8 = 0x31;
    const ASN1_INTEGER: u8 = 0x02;
    const ASN1_BIT_STRING: u8 = 0x03;
    const ASN1_OCTET_STRING: u8 = 0x04;
    const ASN1_NULL: u8 = 0x05;
    const ASN1_OID: u8 = 0x06;
    const ASN1_UTF8_STRING: u8 = 0x0C;
    const ASN1_PRINTABLE_STRING: u8 = 0x13;
    const ASN1_T61_STRING: u8 = 0x14;
    const ASN1_IA5_STRING: u8 = 0x16;
    const ASN1_UTC_TIME: u8 = 0x17;
    const ASN1_GENERALIZED_TIME: u8 = 0x18;
    const ASN1_CONTEXT_0: u8 = 0xA0;
    const ASN1_CONTEXT_1: u8 = 0xA1;
    const ASN1_CONTEXT_3: u8 = 0xA3;

    // PKCS#7 OID: 1.2.840.113549.1.7.2 (signedData)
    const OID_PKCS7_SIGNED_DATA = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };

    // Signature algorithm OIDs
    pub const OID_SHA1_WITH_RSA = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 };
    pub const OID_SHA256_WITH_RSA = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
    pub const OID_SHA384_WITH_RSA = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };
    pub const OID_SHA512_WITH_RSA = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D };
    pub const OID_SHA256_WITH_ECDSA = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    pub const OID_SHA384_WITH_ECDSA = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
    pub const OID_SHA256_WITH_DSA = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02 };

    // Public key algorithm OIDs
    pub const OID_RSA_ENCRYPTION = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    pub const OID_EC_PUBLIC_KEY = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    pub const OID_DSA = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01 };

    // Distinguished name attribute OIDs
    pub const OID_COMMON_NAME = [_]u8{ 0x55, 0x04, 0x03 };
    pub const OID_COUNTRY = [_]u8{ 0x55, 0x04, 0x06 };
    pub const OID_LOCALITY = [_]u8{ 0x55, 0x04, 0x07 };
    pub const OID_STATE = [_]u8{ 0x55, 0x04, 0x08 };
    pub const OID_ORGANIZATION = [_]u8{ 0x55, 0x04, 0x0A };
    pub const OID_ORG_UNIT = [_]u8{ 0x55, 0x04, 0x0B };

    /// Initialize a new certificate parser
    pub fn init(allocator: std.mem.Allocator) CertificateParser {
        return .{ .allocator = allocator };
    }

    /// Clean up resources (no-op for now, but kept for API consistency)
    pub fn deinit(self: *CertificateParser) void {
        _ = self;
    }

    /// Parse PKCS#7 signature file (.RSA, .DSA, .EC)
    /// Returns certificate information from the first certificate in the chain
    pub fn parsePkcs7(self: *CertificateParser, data: []const u8) CertError!CertificateInfo {
        if (data.len < 10) return CertError.TruncatedData;

        // Parse outer ContentInfo SEQUENCE
        var pos: usize = 0;
        const content_info = try parseAsn1Element(data, &pos);
        if (content_info.tag != ASN1_SEQUENCE) return CertError.InvalidFormat;

        // Parse contentType OID
        const content_type = try parseAsn1Element(data, &pos);
        if (content_type.tag != ASN1_OID) return CertError.InvalidFormat;

        // Verify it's signedData
        if (!std.mem.eql(u8, content_type.data, &OID_PKCS7_SIGNED_DATA)) {
            return CertError.InvalidFormat;
        }

        // Parse [0] EXPLICIT content
        const explicit_content = try parseAsn1Element(data, &pos);
        if (explicit_content.tag != ASN1_CONTEXT_0) return CertError.InvalidFormat;

        // Parse SignedData SEQUENCE
        const signed_data_elem = try parseAsn1Element(data, &pos);
        if (signed_data_elem.tag != ASN1_SEQUENCE) return CertError.InvalidFormat;

        // Parse version INTEGER
        _ = try parseAsn1Element(data, &pos);

        // Parse digestAlgorithms SET
        _ = try parseAsn1Element(data, &pos);

        // Parse encapContentInfo SEQUENCE
        _ = try parseAsn1Element(data, &pos);

        // Parse certificates [0] IMPLICIT (optional)
        const cert_set = try parseAsn1Element(data, &pos);
        if (cert_set.tag != ASN1_CONTEXT_0) return CertError.NoCertificateFound;

        // Find the first certificate in the set
        var cert_pos: usize = 0;
        const cert_data = cert_set.data;
        const cert_elem = try parseAsn1Element(cert_data, &cert_pos);
        if (cert_elem.tag != ASN1_SEQUENCE) return CertError.InvalidFormat;

        // Get the raw certificate data (including tag and length)
        const raw_cert_start = pos - cert_set.data.len;
        const raw_cert = data[raw_cert_start .. raw_cert_start + cert_pos];

        return try self.parseCertificate(cert_elem.data, raw_cert);
    }

    /// Parse an X.509 certificate
    fn parseCertificate(self: *CertificateParser, cert_data: []const u8, raw_cert: []const u8) CertError!CertificateInfo {
        var pos: usize = 0;

        // Parse TBSCertificate SEQUENCE
        const tbs_cert = try parseAsn1Element(cert_data, &pos);
        if (tbs_cert.tag != ASN1_SEQUENCE) return CertError.InvalidFormat;

        var tbs_pos: usize = 0;
        const tbs_data = tbs_cert.data;

        // Parse version [0] EXPLICIT (optional, default v1)
        var version_elem = try parseAsn1Element(tbs_data, &tbs_pos);
        if (version_elem.tag == ASN1_CONTEXT_0) {
            // Skip version, parse next element
            version_elem = try parseAsn1Element(tbs_data, &tbs_pos);
        }

        // Parse serialNumber INTEGER
        const serial_elem = version_elem;
        if (serial_elem.tag != ASN1_INTEGER) return CertError.InvalidFormat;
        const serial_number = try self.formatHex(serial_elem.data);
        errdefer self.allocator.free(serial_number);

        // Parse signature AlgorithmIdentifier
        const sig_alg_elem = try parseAsn1Element(tbs_data, &tbs_pos);
        if (sig_alg_elem.tag != ASN1_SEQUENCE) return CertError.InvalidFormat;
        const signature_algorithm = try self.parseAlgorithmIdentifier(sig_alg_elem.data);
        errdefer self.allocator.free(signature_algorithm);

        // Parse issuer Name
        const issuer_elem = try parseAsn1Element(tbs_data, &tbs_pos);
        if (issuer_elem.tag != ASN1_SEQUENCE) return CertError.InvalidFormat;
        const issuer = try self.parseDistinguishedName(issuer_elem.data);
        errdefer self.allocator.free(issuer);

        // Parse validity SEQUENCE
        const validity_elem = try parseAsn1Element(tbs_data, &tbs_pos);
        if (validity_elem.tag != ASN1_SEQUENCE) return CertError.InvalidFormat;
        const validity = try parseValidity(validity_elem.data);

        // Parse subject Name
        const subject_elem = try parseAsn1Element(tbs_data, &tbs_pos);
        if (subject_elem.tag != ASN1_SEQUENCE) return CertError.InvalidFormat;
        const subject = try self.parseDistinguishedName(subject_elem.data);
        errdefer self.allocator.free(subject);

        // Parse subjectPublicKeyInfo SEQUENCE
        const spki_elem = try parseAsn1Element(tbs_data, &tbs_pos);
        if (spki_elem.tag != ASN1_SEQUENCE) return CertError.InvalidFormat;
        const pub_key_info = try self.parseSubjectPublicKeyInfo(spki_elem.data);

        // Compute fingerprints
        const fingerprint_md5 = computeMd5Fingerprint(raw_cert);
        const fingerprint_sha256 = computeSha256Fingerprint(raw_cert);

        return CertificateInfo{
            .subject = subject,
            .issuer = issuer,
            .serial_number = serial_number,
            .not_before = validity.not_before,
            .not_after = validity.not_after,
            .fingerprint_md5 = fingerprint_md5,
            .fingerprint_sha256 = fingerprint_sha256,
            .signature_algorithm = signature_algorithm,
            .public_key_algorithm = pub_key_info.algorithm,
            .public_key_size = pub_key_info.key_size,
            .raw_certificate = raw_cert,
            .allocator = self.allocator,
        };
    }

    /// Extract certificate from APK META-INF directory
    pub fn extractFromApk(self: *CertificateParser, archive: *const zip.ZipParser) CertError!CertificateInfo {
        // Look for signature files in META-INF/
        const patterns = [_][]const u8{
            "META-INF/*.RSA",
            "META-INF/*.DSA",
            "META-INF/*.EC",
        };

        for (patterns) |pattern| {
            if (archive.findFileGlob(pattern)) |entry| {
                const data = archive.getDecompressedData(self.allocator, entry) catch {
                    continue;
                };
                defer self.allocator.free(data);

                return self.parsePkcs7(data) catch |err| {
                    // Try next pattern on error
                    if (err == CertError.InvalidFormat or err == CertError.NoCertificateFound) {
                        continue;
                    }
                    return err;
                };
            }
        }

        return CertError.NoCertificateFound;
    }

    /// Check if a file is a PKCS#7 signature file based on extension
    pub fn isSignatureFile(filename: []const u8) bool {
        if (filename.len < 4) return false;

        // Check if in META-INF directory
        if (!std.mem.startsWith(u8, filename, "META-INF/")) return false;

        // Check extension
        const lower_ext = filename[filename.len - 4 ..];
        return std.mem.eql(u8, lower_ext, ".RSA") or
            std.mem.eql(u8, lower_ext, ".DSA") or
            (filename.len >= 3 and std.mem.eql(u8, filename[filename.len - 3 ..], ".EC"));
    }

    /// Compute MD5 fingerprint of certificate data
    pub fn computeMd5Fingerprint(cert_data: []const u8) [16]u8 {
        var hasher = std.crypto.hash.Md5.init(.{});
        hasher.update(cert_data);
        var result: [16]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    /// Compute SHA-256 fingerprint of certificate data
    pub fn computeSha256Fingerprint(cert_data: []const u8) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(cert_data);
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    /// Format fingerprint as colon-separated hex string
    pub fn formatFingerprintHex(allocator: std.mem.Allocator, fingerprint: []const u8) CertError![]u8 {
        if (fingerprint.len == 0) {
            return allocator.dupe(u8, "") catch return CertError.OutOfMemory;
        }

        const result_len = fingerprint.len * 3 - 1; // "XX:XX:XX..."
        var result = allocator.alloc(u8, result_len) catch return CertError.OutOfMemory;

        const hex_chars = "0123456789ABCDEF";
        var out_idx: usize = 0;
        for (fingerprint, 0..) |byte, i| {
            result[out_idx] = hex_chars[byte >> 4];
            result[out_idx + 1] = hex_chars[byte & 0x0F];
            out_idx += 2;
            if (i < fingerprint.len - 1) {
                result[out_idx] = ':';
                out_idx += 1;
            }
        }

        return result;
    }

    // ========================================================================
    // Private helper functions
    // ========================================================================

    const Asn1Element = struct {
        tag: u8,
        data: []const u8,
    };

    /// Parse an ASN.1 element (tag + length + data)
    fn parseAsn1Element(data: []const u8, pos: *usize) CertError!Asn1Element {
        if (pos.* >= data.len) return CertError.TruncatedData;

        const tag = data[pos.*];
        pos.* += 1;

        if (pos.* >= data.len) return CertError.TruncatedData;

        // Parse length
        const length = try parseAsn1Length(data, pos);

        if (pos.* + length > data.len) return CertError.TruncatedData;

        const elem_data = data[pos.* .. pos.* + length];
        pos.* += length;

        return Asn1Element{ .tag = tag, .data = elem_data };
    }

    /// Parse ASN.1 length encoding
    pub fn parseAsn1Length(data: []const u8, pos: *usize) CertError!usize {
        if (pos.* >= data.len) return CertError.TruncatedData;

        const first_byte = data[pos.*];
        pos.* += 1;

        if (first_byte < 0x80) {
            // Short form: length is in the byte itself
            return first_byte;
        }

        if (first_byte == 0x80) {
            // Indefinite length (not supported)
            return CertError.InvalidAsn1;
        }

        // Long form: first byte indicates number of length bytes
        const num_bytes = first_byte & 0x7F;
        if (num_bytes > 4) return CertError.InvalidAsn1;
        if (pos.* + num_bytes > data.len) return CertError.TruncatedData;

        var length: usize = 0;
        for (0..num_bytes) |_| {
            length = (length << 8) | data[pos.*];
            pos.* += 1;
        }

        return length;
    }

    /// Parse algorithm identifier and return human-readable name
    fn parseAlgorithmIdentifier(self: *CertificateParser, data: []const u8) CertError![]u8 {
        var pos: usize = 0;
        const oid_elem = try parseAsn1Element(data, &pos);
        if (oid_elem.tag != ASN1_OID) return CertError.InvalidFormat;

        const name = getAlgorithmName(oid_elem.data);
        return self.allocator.dupe(u8, name) catch return CertError.OutOfMemory;
    }

    /// Get algorithm name from OID
    pub fn getAlgorithmName(oid: []const u8) []const u8 {
        if (std.mem.eql(u8, oid, &OID_SHA1_WITH_RSA)) return "SHA1withRSA";
        if (std.mem.eql(u8, oid, &OID_SHA256_WITH_RSA)) return "SHA256withRSA";
        if (std.mem.eql(u8, oid, &OID_SHA384_WITH_RSA)) return "SHA384withRSA";
        if (std.mem.eql(u8, oid, &OID_SHA512_WITH_RSA)) return "SHA512withRSA";
        if (std.mem.eql(u8, oid, &OID_SHA256_WITH_ECDSA)) return "SHA256withECDSA";
        if (std.mem.eql(u8, oid, &OID_SHA384_WITH_ECDSA)) return "SHA384withECDSA";
        if (std.mem.eql(u8, oid, &OID_SHA256_WITH_DSA)) return "SHA256withDSA";
        if (std.mem.eql(u8, oid, &OID_RSA_ENCRYPTION)) return "RSA";
        if (std.mem.eql(u8, oid, &OID_EC_PUBLIC_KEY)) return "EC";
        if (std.mem.eql(u8, oid, &OID_DSA)) return "DSA";
        return "Unknown";
    }

    /// Parse distinguished name and return formatted string
    fn parseDistinguishedName(self: *CertificateParser, data: []const u8) CertError![]u8 {
        var result = std.ArrayListUnmanaged(u8){};
        errdefer result.deinit(self.allocator);

        var pos: usize = 0;
        var first = true;

        while (pos < data.len) {
            // Parse RDN SET
            const rdn_set = parseAsn1Element(data, &pos) catch break;
            if (rdn_set.tag != ASN1_SET) continue;

            // Parse AttributeTypeAndValue SEQUENCE
            var rdn_pos: usize = 0;
            while (rdn_pos < rdn_set.data.len) {
                const atv = parseAsn1Element(rdn_set.data, &rdn_pos) catch break;
                if (atv.tag != ASN1_SEQUENCE) continue;

                // Parse type OID and value
                var atv_pos: usize = 0;
                const type_oid = parseAsn1Element(atv.data, &atv_pos) catch continue;
                if (type_oid.tag != ASN1_OID) continue;

                const value_elem = parseAsn1Element(atv.data, &atv_pos) catch continue;

                // Get attribute name
                const attr_name = getAttributeName(type_oid.data);
                if (attr_name.len == 0) continue;

                // Add separator
                if (!first) {
                    result.appendSlice(self.allocator, ", ") catch return CertError.OutOfMemory;
                }
                first = false;

                // Add "Name=Value"
                result.appendSlice(self.allocator, attr_name) catch return CertError.OutOfMemory;
                result.append(self.allocator, '=') catch return CertError.OutOfMemory;
                result.appendSlice(self.allocator, value_elem.data) catch return CertError.OutOfMemory;
            }
        }

        if (result.items.len == 0) {
            result.deinit(self.allocator);
            return self.allocator.dupe(u8, "Unknown") catch return CertError.OutOfMemory;
        }

        return result.toOwnedSlice(self.allocator) catch return CertError.OutOfMemory;
    }

    /// Get attribute name from OID
    pub fn getAttributeName(oid: []const u8) []const u8 {
        if (std.mem.eql(u8, oid, &OID_COMMON_NAME)) return "CN";
        if (std.mem.eql(u8, oid, &OID_COUNTRY)) return "C";
        if (std.mem.eql(u8, oid, &OID_LOCALITY)) return "L";
        if (std.mem.eql(u8, oid, &OID_STATE)) return "ST";
        if (std.mem.eql(u8, oid, &OID_ORGANIZATION)) return "O";
        if (std.mem.eql(u8, oid, &OID_ORG_UNIT)) return "OU";
        return "";
    }

    const Validity = struct {
        not_before: i64,
        not_after: i64,
    };

    /// Parse validity period
    fn parseValidity(data: []const u8) CertError!Validity {
        var pos: usize = 0;

        // Parse notBefore
        const not_before_elem = try parseAsn1Element(data, &pos);
        const not_before = try parseTime(not_before_elem);

        // Parse notAfter
        const not_after_elem = try parseAsn1Element(data, &pos);
        const not_after = try parseTime(not_after_elem);

        return Validity{
            .not_before = not_before,
            .not_after = not_after,
        };
    }

    /// Parse UTCTime or GeneralizedTime to Unix timestamp
    fn parseTime(elem: Asn1Element) CertError!i64 {
        if (elem.tag == ASN1_UTC_TIME) {
            return parseUtcTime(elem.data);
        } else if (elem.tag == ASN1_GENERALIZED_TIME) {
            return parseGeneralizedTime(elem.data);
        }
        return CertError.InvalidFormat;
    }

    /// Parse UTCTime format: YYMMDDHHMMSSZ
    pub fn parseUtcTime(data: []const u8) CertError!i64 {
        if (data.len < 13) return CertError.InvalidUtcTime;

        const year_2digit = parseDigits(data[0..2]) orelse return CertError.InvalidUtcTime;
        const year: i32 = if (year_2digit >= 50) 1900 + year_2digit else 2000 + year_2digit;
        const month = parseDigits(data[2..4]) orelse return CertError.InvalidUtcTime;
        const day = parseDigits(data[4..6]) orelse return CertError.InvalidUtcTime;
        const hour = parseDigits(data[6..8]) orelse return CertError.InvalidUtcTime;
        const minute = parseDigits(data[8..10]) orelse return CertError.InvalidUtcTime;
        const second = parseDigits(data[10..12]) orelse return CertError.InvalidUtcTime;

        return dateToTimestamp(year, month, day, hour, minute, second);
    }

    /// Parse GeneralizedTime format: YYYYMMDDHHMMSSZ
    pub fn parseGeneralizedTime(data: []const u8) CertError!i64 {
        if (data.len < 15) return CertError.InvalidGeneralizedTime;

        const year = parseDigits4(data[0..4]) orelse return CertError.InvalidGeneralizedTime;
        const month = parseDigits(data[4..6]) orelse return CertError.InvalidGeneralizedTime;
        const day = parseDigits(data[6..8]) orelse return CertError.InvalidGeneralizedTime;
        const hour = parseDigits(data[8..10]) orelse return CertError.InvalidGeneralizedTime;
        const minute = parseDigits(data[10..12]) orelse return CertError.InvalidGeneralizedTime;
        const second = parseDigits(data[12..14]) orelse return CertError.InvalidGeneralizedTime;

        return dateToTimestamp(year, month, day, hour, minute, second);
    }

    /// Parse 2-digit number
    fn parseDigits(data: []const u8) ?i32 {
        if (data.len < 2) return null;
        const d1 = data[0];
        const d2 = data[1];
        if (d1 < '0' or d1 > '9' or d2 < '0' or d2 > '9') return null;
        return @as(i32, d1 - '0') * 10 + @as(i32, d2 - '0');
    }

    /// Parse 4-digit number
    fn parseDigits4(data: []const u8) ?i32 {
        if (data.len < 4) return null;
        const d1 = parseDigits(data[0..2]) orelse return null;
        const d2 = parseDigits(data[2..4]) orelse return null;
        return d1 * 100 + d2;
    }

    /// Convert date components to Unix timestamp
    pub fn dateToTimestamp(year: i32, month: i32, day: i32, hour: i32, minute: i32, second: i32) i64 {
        // Days in each month (non-leap year)
        const days_in_month = [_]i32{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

        // Calculate days since epoch (1970-01-01)
        var days: i64 = 0;

        // Add days for years
        var y: i32 = 1970;
        while (y < year) : (y += 1) {
            days += if (isLeapYear(y)) 366 else 365;
        }

        // Add days for months
        var m: usize = 1;
        while (m < @as(usize, @intCast(month))) : (m += 1) {
            days += days_in_month[m - 1];
            if (m == 2 and isLeapYear(year)) {
                days += 1;
            }
        }

        // Add days
        days += day - 1;

        // Convert to seconds and add time
        return days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
    }

    /// Check if year is a leap year
    pub fn isLeapYear(year: i32) bool {
        return (@mod(year, 4) == 0 and @mod(year, 100) != 0) or @mod(year, 400) == 0;
    }

    const PublicKeyInfo = struct {
        algorithm: []u8,
        key_size: u32,
    };

    /// Parse SubjectPublicKeyInfo
    fn parseSubjectPublicKeyInfo(self: *CertificateParser, data: []const u8) CertError!PublicKeyInfo {
        var pos: usize = 0;

        // Parse algorithm SEQUENCE
        const alg_elem = try parseAsn1Element(data, &pos);
        if (alg_elem.tag != ASN1_SEQUENCE) return CertError.InvalidFormat;

        // Parse algorithm OID
        var alg_pos: usize = 0;
        const oid_elem = try parseAsn1Element(alg_elem.data, &alg_pos);
        if (oid_elem.tag != ASN1_OID) return CertError.InvalidFormat;

        const algorithm = try self.allocator.dupe(u8, getPublicKeyAlgorithmName(oid_elem.data));
        errdefer self.allocator.free(algorithm);

        // Parse subjectPublicKey BIT STRING
        const key_elem = try parseAsn1Element(data, &pos);
        if (key_elem.tag != ASN1_BIT_STRING) return CertError.InvalidFormat;

        // Calculate key size based on algorithm and key data
        const key_size = calculateKeySize(oid_elem.data, key_elem.data);

        return PublicKeyInfo{
            .algorithm = algorithm,
            .key_size = key_size,
        };
    }

    /// Get public key algorithm name from OID
    fn getPublicKeyAlgorithmName(oid: []const u8) []const u8 {
        if (std.mem.eql(u8, oid, &OID_RSA_ENCRYPTION)) return "RSA";
        if (std.mem.eql(u8, oid, &OID_EC_PUBLIC_KEY)) return "EC";
        if (std.mem.eql(u8, oid, &OID_DSA)) return "DSA";
        return "Unknown";
    }

    /// Calculate key size in bits
    fn calculateKeySize(alg_oid: []const u8, key_data: []const u8) u32 {
        if (key_data.len < 2) return 0;

        // Skip the unused bits byte in BIT STRING
        const actual_key = key_data[1..];

        if (std.mem.eql(u8, alg_oid, &OID_RSA_ENCRYPTION)) {
            // RSA: key size is the modulus size
            // The key data is a SEQUENCE containing INTEGER (modulus) and INTEGER (exponent)
            var pos: usize = 0;
            const seq = parseAsn1Element(actual_key, &pos) catch return 0;
            if (seq.tag != ASN1_SEQUENCE) return 0;

            var seq_pos: usize = 0;
            const modulus = parseAsn1Element(seq.data, &seq_pos) catch return 0;
            if (modulus.tag != ASN1_INTEGER) return 0;

            // Key size in bits (subtract leading zero byte if present)
            var mod_data = modulus.data;
            if (mod_data.len > 0 and mod_data[0] == 0) {
                mod_data = mod_data[1..];
            }
            return @intCast(mod_data.len * 8);
        }

        if (std.mem.eql(u8, alg_oid, &OID_EC_PUBLIC_KEY)) {
            // EC: key size depends on curve, estimate from key length
            // Common sizes: 256-bit (P-256), 384-bit (P-384), 521-bit (P-521)
            const key_len = actual_key.len;
            if (key_len <= 65) return 256; // P-256: 32*2 + 1 = 65 bytes
            if (key_len <= 97) return 384; // P-384: 48*2 + 1 = 97 bytes
            return 521; // P-521: 66*2 + 1 = 133 bytes
        }

        if (std.mem.eql(u8, alg_oid, &OID_DSA)) {
            // DSA: key size is the p parameter size
            return @intCast(actual_key.len * 8);
        }

        return 0;
    }

    /// Format bytes as hex string
    fn formatHex(self: *CertificateParser, data: []const u8) CertError![]u8 {
        if (data.len == 0) {
            return self.allocator.dupe(u8, "00") catch return CertError.OutOfMemory;
        }

        var result = self.allocator.alloc(u8, data.len * 2) catch return CertError.OutOfMemory;
        const hex_chars = "0123456789ABCDEF";

        for (data, 0..) |byte, i| {
            result[i * 2] = hex_chars[byte >> 4];
            result[i * 2 + 1] = hex_chars[byte & 0x0F];
        }

        return result;
    }
};


// ============================================================================
// Unit Tests
// ============================================================================

test "CertificateParser.computeMd5Fingerprint computes correct hash" {
    const data = "test certificate data";
    const fingerprint = CertificateParser.computeMd5Fingerprint(data);
    try std.testing.expectEqual(@as(usize, 16), fingerprint.len);
    // MD5 of "test certificate data" should be consistent
    try std.testing.expect(fingerprint[0] != 0 or fingerprint[1] != 0);
}

test "CertificateParser.computeSha256Fingerprint computes correct hash" {
    const data = "test certificate data";
    const fingerprint = CertificateParser.computeSha256Fingerprint(data);
    try std.testing.expectEqual(@as(usize, 32), fingerprint.len);
    // SHA-256 should produce non-zero output
    try std.testing.expect(fingerprint[0] != 0 or fingerprint[1] != 0);
}

test "CertificateParser.formatFingerprintHex formats correctly" {
    const fingerprint = [_]u8{ 0xAB, 0xCD, 0xEF, 0x12 };
    const hex = try CertificateParser.formatFingerprintHex(std.testing.allocator, &fingerprint);
    defer std.testing.allocator.free(hex);

    try std.testing.expectEqualStrings("AB:CD:EF:12", hex);
}

test "CertificateParser.formatFingerprintHex handles empty input" {
    const empty: []const u8 = &.{};
    const hex = try CertificateParser.formatFingerprintHex(std.testing.allocator, empty);
    defer std.testing.allocator.free(hex);

    try std.testing.expectEqualStrings("", hex);
}

test "CertificateParser.formatFingerprintHex handles single byte" {
    const single = [_]u8{0xFF};
    const hex = try CertificateParser.formatFingerprintHex(std.testing.allocator, &single);
    defer std.testing.allocator.free(hex);

    try std.testing.expectEqualStrings("FF", hex);
}

test "CertificateParser.isSignatureFile detects RSA files" {
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/CERT.RSA"));
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/ANDROIDDEBUGKEY.RSA"));
}

test "CertificateParser.isSignatureFile detects DSA files" {
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/CERT.DSA"));
}

test "CertificateParser.isSignatureFile detects EC files" {
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/CERT.EC"));
}

test "CertificateParser.isSignatureFile rejects non-signature files" {
    try std.testing.expect(!CertificateParser.isSignatureFile("META-INF/MANIFEST.MF"));
    try std.testing.expect(!CertificateParser.isSignatureFile("META-INF/CERT.SF"));
    try std.testing.expect(!CertificateParser.isSignatureFile("classes.dex"));
    try std.testing.expect(!CertificateParser.isSignatureFile("AndroidManifest.xml"));
    try std.testing.expect(!CertificateParser.isSignatureFile("CERT.RSA")); // Not in META-INF
}

test "CertificateParser.parsePkcs7 returns TruncatedData for short input" {
    var parser = CertificateParser.init(std.testing.allocator);
    defer parser.deinit();

    const result = parser.parsePkcs7("short");
    try std.testing.expectError(CertificateParser.CertError.TruncatedData, result);
}

test "CertificateParser.parsePkcs7 returns InvalidFormat for non-PKCS7 data" {
    var parser = CertificateParser.init(std.testing.allocator);
    defer parser.deinit();

    // Create invalid ASN.1 data (not a SEQUENCE)
    const invalid_data = [_]u8{ 0x02, 0x01, 0x00 } ++ [_]u8{0} ** 20;
    const result = parser.parsePkcs7(&invalid_data);
    try std.testing.expectError(CertificateParser.CertError.InvalidFormat, result);
}

test "parseAsn1Length handles short form" {
    var pos: usize = 0;
    const data = [_]u8{0x10}; // Length 16
    const length = try CertificateParser.parseAsn1Length(&data, &pos);
    try std.testing.expectEqual(@as(usize, 16), length);
    try std.testing.expectEqual(@as(usize, 1), pos);
}

test "parseAsn1Length handles long form 1 byte" {
    var pos: usize = 0;
    const data = [_]u8{ 0x81, 0x80 }; // Length 128
    const length = try CertificateParser.parseAsn1Length(&data, &pos);
    try std.testing.expectEqual(@as(usize, 128), length);
    try std.testing.expectEqual(@as(usize, 2), pos);
}

test "parseAsn1Length handles long form 2 bytes" {
    var pos: usize = 0;
    const data = [_]u8{ 0x82, 0x01, 0x00 }; // Length 256
    const length = try CertificateParser.parseAsn1Length(&data, &pos);
    try std.testing.expectEqual(@as(usize, 256), length);
    try std.testing.expectEqual(@as(usize, 3), pos);
}

test "parseAsn1Length rejects indefinite length" {
    var pos: usize = 0;
    const data = [_]u8{0x80}; // Indefinite length
    const result = CertificateParser.parseAsn1Length(&data, &pos);
    try std.testing.expectError(CertificateParser.CertError.InvalidAsn1, result);
}

test "parseUtcTime parses valid time" {
    // 230615120000Z = June 15, 2023, 12:00:00 UTC
    const time_str = "230615120000Z";
    const timestamp = try CertificateParser.parseUtcTime(time_str);
    // Verify it's a reasonable timestamp (after 2023-01-01)
    try std.testing.expect(timestamp > 1672531200);
}

test "parseUtcTime handles Y2K correctly" {
    // 991231235959Z = December 31, 1999, 23:59:59 UTC
    const time_str = "991231235959Z";
    const timestamp = try CertificateParser.parseUtcTime(time_str);
    // Should be in 1999, not 2099
    try std.testing.expect(timestamp < 1000000000);
}

test "parseGeneralizedTime parses valid time" {
    // 20230615120000Z = June 15, 2023, 12:00:00 UTC
    const time_str = "20230615120000Z";
    const timestamp = try CertificateParser.parseGeneralizedTime(time_str);
    // Verify it's a reasonable timestamp
    try std.testing.expect(timestamp > 1672531200);
}

test "getAlgorithmName returns correct names" {
    try std.testing.expectEqualStrings("SHA256withRSA", CertificateParser.getAlgorithmName(&CertificateParser.OID_SHA256_WITH_RSA));
    try std.testing.expectEqualStrings("SHA1withRSA", CertificateParser.getAlgorithmName(&CertificateParser.OID_SHA1_WITH_RSA));
    try std.testing.expectEqualStrings("SHA256withECDSA", CertificateParser.getAlgorithmName(&CertificateParser.OID_SHA256_WITH_ECDSA));
    try std.testing.expectEqualStrings("RSA", CertificateParser.getAlgorithmName(&CertificateParser.OID_RSA_ENCRYPTION));
    try std.testing.expectEqualStrings("EC", CertificateParser.getAlgorithmName(&CertificateParser.OID_EC_PUBLIC_KEY));
    try std.testing.expectEqualStrings("DSA", CertificateParser.getAlgorithmName(&CertificateParser.OID_DSA));
}

test "getAlgorithmName returns Unknown for unrecognized OID" {
    const unknown_oid = [_]u8{ 0x01, 0x02, 0x03 };
    try std.testing.expectEqualStrings("Unknown", CertificateParser.getAlgorithmName(&unknown_oid));
}

test "getAttributeName returns correct names" {
    try std.testing.expectEqualStrings("CN", CertificateParser.getAttributeName(&CertificateParser.OID_COMMON_NAME));
    try std.testing.expectEqualStrings("O", CertificateParser.getAttributeName(&CertificateParser.OID_ORGANIZATION));
    try std.testing.expectEqualStrings("OU", CertificateParser.getAttributeName(&CertificateParser.OID_ORG_UNIT));
    try std.testing.expectEqualStrings("C", CertificateParser.getAttributeName(&CertificateParser.OID_COUNTRY));
    try std.testing.expectEqualStrings("ST", CertificateParser.getAttributeName(&CertificateParser.OID_STATE));
    try std.testing.expectEqualStrings("L", CertificateParser.getAttributeName(&CertificateParser.OID_LOCALITY));
}

test "isLeapYear correctly identifies leap years" {
    try std.testing.expect(CertificateParser.isLeapYear(2000)); // Divisible by 400
    try std.testing.expect(CertificateParser.isLeapYear(2004)); // Divisible by 4
    try std.testing.expect(CertificateParser.isLeapYear(2020)); // Divisible by 4
    try std.testing.expect(!CertificateParser.isLeapYear(1900)); // Divisible by 100 but not 400
    try std.testing.expect(!CertificateParser.isLeapYear(2001)); // Not divisible by 4
    try std.testing.expect(!CertificateParser.isLeapYear(2023)); // Not divisible by 4
}

test "dateToTimestamp computes correct Unix timestamp" {
    // January 1, 1970, 00:00:00 UTC = 0
    const epoch = CertificateParser.dateToTimestamp(1970, 1, 1, 0, 0, 0);
    try std.testing.expectEqual(@as(i64, 0), epoch);

    // January 1, 2000, 00:00:00 UTC = 946684800
    const y2k = CertificateParser.dateToTimestamp(2000, 1, 1, 0, 0, 0);
    try std.testing.expectEqual(@as(i64, 946684800), y2k);
}
