const std = @import("std");

// Import buffer_pool from perf module
const buffer_pool = @import("../perf/buffer_pool.zig");
const SimdString = buffer_pool.SimdString;

/// Android Binary XML (AXML) Parser - Optimized for performance with SIMD
/// Parses the binary XML format used in AndroidManifest.xml within APK files
pub const AxmlParser = struct {
    // ============================================================================
    // Manifest Metadata Types
    // ============================================================================

    /// Install location preference for the application
    pub const InstallLocation = enum {
        auto,
        internal_only,
        prefer_external,

        /// Parse install location from string value
        pub fn fromString(value: []const u8) InstallLocation {
            // installLocation values: 0=auto, 1=internalOnly, 2=preferExternal
            if (std.mem.eql(u8, value, "1") or std.mem.eql(u8, value, "internalOnly")) {
                return .internal_only;
            } else if (std.mem.eql(u8, value, "2") or std.mem.eql(u8, value, "preferExternal")) {
                return .prefer_external;
            }
            return .auto;
        }
    };

    /// Permission with optional SDK constraint
    pub const Permission = struct {
        name: []const u8,
        max_sdk_version: ?u32,
    };

    /// Intent filter for activities/services/receivers
    pub const IntentFilter = struct {
        actions: []const []const u8,
        categories: []const []const u8,
        data_schemes: []const []const u8,
    };

    /// Activity component from manifest
    pub const Activity = struct {
        name: []const u8,
        exported: ?bool,
        enabled: bool,
        intent_filters: []const IntentFilter,
    };

    /// Service component from manifest
    pub const Service = struct {
        name: []const u8,
        exported: ?bool,
        enabled: bool,
        intent_filters: []const IntentFilter,
    };

    /// Broadcast receiver component from manifest
    pub const Receiver = struct {
        name: []const u8,
        exported: ?bool,
        enabled: bool,
        intent_filters: []const IntentFilter,
    };

    /// Complete manifest metadata extracted in one pass
    pub const ManifestMetadata = struct {
        package_id: []const u8,
        app_name: []const u8,
        version_code: []const u8,
        version_name: []const u8,
        min_sdk_version: u32,
        target_sdk_version: ?u32,
        install_location: InstallLocation,
        permissions: []const Permission,
        features: []const Feature,
        is_debuggable: bool,
    };
    /// Parsed XML elements
    elements: []const XmlElement,
    /// String pool for attribute values
    string_pool: []const []const u8,
    /// Allocator used for dynamic allocations
    allocator: std.mem.Allocator,
    /// Arena for batch deallocations (owned memory)
    arena: ?std.heap.ArenaAllocator,

    /// XML element representation - optimized field ordering for cache efficiency
    pub const XmlElement = struct {
        /// Element attributes (pointer first for alignment)
        attributes: []const XmlAttribute,
        /// Element name (e.g., "manifest", "application", "uses-sdk")
        name: []const u8,
        /// Element namespace (may be empty)
        namespace: []const u8,
        /// Depth in the XML tree (0 = root)
        depth: u32,
    };

    /// XML attribute representation - optimized layout
    pub const XmlAttribute = struct {
        /// Attribute name (e.g., "package", "versionCode")
        name: []const u8,
        /// Attribute namespace (e.g., "android")
        namespace: []const u8,
        /// Attribute value as string
        value: []const u8,
        /// Raw value type
        value_type: ValueType,
    };

    /// Attribute value types
    pub const ValueType = enum(u8) {
        null_type = 0x00,
        reference = 0x01,
        attribute = 0x02,
        string = 0x03,
        float = 0x04,
        dimension = 0x05,
        fraction = 0x06,
        int_dec = 0x10,
        int_hex = 0x11,
        int_boolean = 0x12,
        int_color_argb8 = 0x1c,
        int_color_rgb8 = 0x1d,
        int_color_argb4 = 0x1e,
        int_color_rgb4 = 0x1f,
    };

    /// Errors that can occur during AXML parsing
    pub const AxmlError = error{
        InvalidFormat,
        TruncatedData,
        OutOfMemory,
        InvalidStringPool,
        InvalidChunkType,
    };

    /// AXML chunk types - comptime constants
    const CHUNK_AXML_FILE: u16 = 0x0003;
    const CHUNK_STRING_POOL: u16 = 0x0001;
    const CHUNK_RESOURCE_IDS: u16 = 0x0180;
    const CHUNK_START_NAMESPACE: u16 = 0x0100;
    const CHUNK_END_NAMESPACE: u16 = 0x0101;
    const CHUNK_START_ELEMENT: u16 = 0x0102;
    const CHUNK_END_ELEMENT: u16 = 0x0103;
    const CHUNK_CDATA: u16 = 0x0104;

    /// Pre-allocated capacity hints
    const INITIAL_STRING_POOL_CAPACITY: usize = 256;
    const INITIAL_ELEMENT_CAPACITY: usize = 64;
    const INITIAL_ATTRIBUTE_CAPACITY: usize = 16;

    /// Parse AXML data with arena allocator for efficient memory management
    pub fn parse(allocator: std.mem.Allocator, data: []const u8) AxmlError!AxmlParser {
        if (data.len < 8) {
            @branchHint(.cold);
            return AxmlError.InvalidFormat;
        }

        // Check AXML magic
        const magic = std.mem.readInt(u16, data[0..2], .little);
        if (magic != CHUNK_AXML_FILE) {
            @branchHint(.cold);
            return AxmlError.InvalidFormat;
        }

        const header_size = std.mem.readInt(u16, data[2..4], .little);
        const file_size = std.mem.readInt(u32, data[4..8], .little);

        if (file_size > data.len) {
            @branchHint(.cold);
            return AxmlError.TruncatedData;
        }

        // Use arena allocator for batch allocations - single free at deinit
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const arena_alloc = arena.allocator();

        // Pre-allocate with capacity hints (using unmanaged for Zig 0.15 compatibility)
        var string_pool = std.ArrayListUnmanaged([]const u8){};
        try string_pool.ensureTotalCapacity(arena_alloc, INITIAL_STRING_POOL_CAPACITY);
        var elements = std.ArrayListUnmanaged(XmlElement){};
        try elements.ensureTotalCapacity(arena_alloc, INITIAL_ELEMENT_CAPACITY);

        var offset: usize = header_size;
        var depth: u32 = 0;

        // Main parsing loop - optimized chunk processing
        while (offset + 8 <= data.len) {
            const chunk_type = std.mem.readInt(u16, data[offset..][0..2], .little);
            const chunk_size = std.mem.readInt(u32, data[offset + 4 ..][0..4], .little);

            if (chunk_size < 8) break;
            if (offset + chunk_size > data.len) break;

            const chunk_data = data[offset .. offset + chunk_size];

            switch (chunk_type) {
                CHUNK_STRING_POOL => {
                    try parseStringPoolOptimized(arena_alloc, chunk_data, &string_pool);
                },
                CHUNK_START_ELEMENT => {
                    const elem = try parseStartElementOptimized(arena_alloc, chunk_data, string_pool.items, depth);
                    try elements.append(arena_alloc, elem);
                    depth += 1;
                },
                CHUNK_END_ELEMENT => {
                    if (depth > 0) depth -= 1;
                },
                else => {},
            }

            offset += chunk_size;
        }

        return AxmlParser{
            .elements = try elements.toOwnedSlice(arena_alloc),
            .string_pool = try string_pool.toOwnedSlice(arena_alloc),
            .allocator = allocator,
            .arena = arena,
        };
    }

    /// Deinitialize the parser - single arena free
    pub fn deinit(self: *AxmlParser) void {
        if (self.arena) |*arena| {
            arena.deinit();
        }
        self.elements = &.{};
        self.string_pool = &.{};
        self.arena = null;
    }

    /// Get the root element (manifest) - inline for hot path
    pub inline fn getRoot(self: *const AxmlParser) ?*const XmlElement {
        return if (self.elements.len > 0) &self.elements[0] else null;
    }

    /// Find element by name - optimized with SIMD string comparison
    pub fn findElement(self: *const AxmlParser, name: []const u8) ?*const XmlElement {
        for (self.elements) |*elem| {
            // Use SIMD-optimized string comparison for better performance
            if (SimdString.equals(elem.name, name)) {
                return elem;
            }
        }
        return null;
    }

    /// Get attribute value from an element - inline wrapper
    pub inline fn getAttribute(self: *const AxmlParser, element_name: []const u8, attr_name: []const u8) ?[]const u8 {
        const elem = self.findElement(element_name) orelse return null;
        return getAttributeFromElementFast(elem, attr_name);
    }

    /// Get attribute from uses-sdk element
    pub inline fn getUseSdkAttribute(self: *const AxmlParser, attr_name: []const u8) ?[]const u8 {
        return self.getAttribute("uses-sdk", attr_name);
    }

    /// Get all permissions - batch allocation
    pub fn getPermissions(self: *const AxmlParser, allocator: std.mem.Allocator) ![][]const u8 {
        // Count first to avoid reallocations
        var count: usize = 0;
        for (self.elements) |*elem| {
            if (std.mem.eql(u8, elem.name, "uses-permission")) {
                if (getAttributeFromElementFast(elem, "name") != null) {
                    count += 1;
                }
            }
        }

        if (count == 0) return &.{};

        var permissions = try allocator.alloc([]const u8, count);
        var idx: usize = 0;

        for (self.elements) |*elem| {
            if (std.mem.eql(u8, elem.name, "uses-permission")) {
                if (getAttributeFromElementFast(elem, "name")) |name| {
                    permissions[idx] = name;
                    idx += 1;
                }
            }
        }

        return permissions[0..idx];
    }

    /// Get all features - batch allocation
    pub fn getFeatures(self: *const AxmlParser, allocator: std.mem.Allocator) ![]Feature {
        var count: usize = 0;
        for (self.elements) |*elem| {
            if (std.mem.eql(u8, elem.name, "uses-feature")) {
                if (getAttributeFromElementFast(elem, "name") != null) {
                    count += 1;
                }
            }
        }

        if (count == 0) return &.{};

        var features = try allocator.alloc(Feature, count);
        var idx: usize = 0;

        for (self.elements) |*elem| {
            if (std.mem.eql(u8, elem.name, "uses-feature")) {
                const name = getAttributeFromElementFast(elem, "name") orelse continue;
                const required_str = getAttributeFromElementFast(elem, "required");
                const required = if (required_str) |r| !std.mem.eql(u8, r, "false") else true;

                features[idx] = .{ .name = name, .required = required };
                idx += 1;
            }
        }

        return features[0..idx];
    }

    /// Feature representation
    pub const Feature = struct {
        name: []const u8,
        required: bool,
    };

    // ============================================================================
    // Manifest Helper Methods
    // ============================================================================

    /// Extract complete manifest metadata in one pass
    /// This is more efficient than calling individual methods as it iterates once
    pub fn extractManifestMetadata(self: *const AxmlParser, allocator: std.mem.Allocator) !ManifestMetadata {
        var package_id: []const u8 = "";
        var app_name: []const u8 = "";
        var version_code: []const u8 = "";
        var version_name: []const u8 = "";
        var min_sdk_version: u32 = 1;
        var target_sdk_version: ?u32 = null;
        var install_location: InstallLocation = .auto;
        var is_debuggable: bool = false;

        // Count permissions and features first
        var permission_count: usize = 0;
        var feature_count: usize = 0;

        for (self.elements) |*elem| {
            if (SimdString.equals(elem.name, "manifest")) {
                // Extract manifest-level attributes
                if (getAttributeFromElementFast(elem, "package")) |pkg| {
                    package_id = pkg;
                }
                if (getAttributeFromElementFast(elem, "versionCode")) |vc| {
                    version_code = vc;
                }
                if (getAttributeFromElementFast(elem, "versionName")) |vn| {
                    version_name = vn;
                }
                if (getAttributeFromElementFast(elem, "installLocation")) |loc| {
                    install_location = InstallLocation.fromString(loc);
                }
            } else if (SimdString.equals(elem.name, "uses-sdk")) {
                // Extract SDK version attributes
                if (getAttributeFromElementFast(elem, "minSdkVersion")) |min_sdk| {
                    min_sdk_version = std.fmt.parseInt(u32, min_sdk, 10) catch 1;
                }
                if (getAttributeFromElementFast(elem, "targetSdkVersion")) |target_sdk| {
                    target_sdk_version = std.fmt.parseInt(u32, target_sdk, 10) catch null;
                }
            } else if (SimdString.equals(elem.name, "application")) {
                // Extract application-level attributes
                if (getAttributeFromElementFast(elem, "label")) |label| {
                    app_name = label;
                }
                if (getAttributeFromElementFast(elem, "debuggable")) |dbg| {
                    is_debuggable = std.mem.eql(u8, dbg, "true") or std.mem.eql(u8, dbg, "1");
                }
            } else if (SimdString.equals(elem.name, "uses-permission")) {
                if (getAttributeFromElementFast(elem, "name") != null) {
                    permission_count += 1;
                }
            } else if (SimdString.equals(elem.name, "uses-feature")) {
                if (getAttributeFromElementFast(elem, "name") != null) {
                    feature_count += 1;
                }
            }
        }

        // Allocate and populate permissions
        var permissions: []Permission = &.{};
        if (permission_count > 0) {
            permissions = try allocator.alloc(Permission, permission_count);
            var perm_idx: usize = 0;

            for (self.elements) |*elem| {
                if (SimdString.equals(elem.name, "uses-permission")) {
                    const name = getAttributeFromElementFast(elem, "name") orelse continue;
                    const max_sdk_str = getAttributeFromElementFast(elem, "maxSdkVersion");
                    const max_sdk = if (max_sdk_str) |s| std.fmt.parseInt(u32, s, 10) catch null else null;

                    permissions[perm_idx] = .{
                        .name = name,
                        .max_sdk_version = max_sdk,
                    };
                    perm_idx += 1;
                }
            }
            permissions = permissions[0..perm_idx];
        }

        // Allocate and populate features
        var features: []Feature = &.{};
        if (feature_count > 0) {
            features = try allocator.alloc(Feature, feature_count);
            var feat_idx: usize = 0;

            for (self.elements) |*elem| {
                if (SimdString.equals(elem.name, "uses-feature")) {
                    const name = getAttributeFromElementFast(elem, "name") orelse continue;
                    const required_str = getAttributeFromElementFast(elem, "required");
                    const required = if (required_str) |r| !std.mem.eql(u8, r, "false") else true;

                    features[feat_idx] = .{ .name = name, .required = required };
                    feat_idx += 1;
                }
            }
            features = features[0..feat_idx];
        }

        return ManifestMetadata{
            .package_id = package_id,
            .app_name = app_name,
            .version_code = version_code,
            .version_name = version_name,
            .min_sdk_version = min_sdk_version,
            .target_sdk_version = target_sdk_version,
            .install_location = install_location,
            .permissions = permissions,
            .features = features,
            .is_debuggable = is_debuggable,
        };
    }

    /// Get all permissions with maxSdkVersion support
    pub fn getPermissionsWithSdk(self: *const AxmlParser, allocator: std.mem.Allocator) ![]Permission {
        // Count first to avoid reallocations
        var count: usize = 0;
        for (self.elements) |*elem| {
            if (std.mem.eql(u8, elem.name, "uses-permission")) {
                if (getAttributeFromElementFast(elem, "name") != null) {
                    count += 1;
                }
            }
        }

        if (count == 0) return &.{};

        var permissions = try allocator.alloc(Permission, count);
        var idx: usize = 0;

        for (self.elements) |*elem| {
            if (std.mem.eql(u8, elem.name, "uses-permission")) {
                const name = getAttributeFromElementFast(elem, "name") orelse continue;
                const max_sdk_str = getAttributeFromElementFast(elem, "maxSdkVersion");
                const max_sdk = if (max_sdk_str) |s| std.fmt.parseInt(u32, s, 10) catch null else null;

                permissions[idx] = .{
                    .name = name,
                    .max_sdk_version = max_sdk,
                };
                idx += 1;
            }
        }

        return permissions[0..idx];
    }

    /// Get all activities from the manifest
    pub fn getActivities(self: *const AxmlParser, allocator: std.mem.Allocator) ![]Activity {
        return self.getComponents(Activity, "activity", allocator);
    }

    /// Get all services from the manifest
    pub fn getServices(self: *const AxmlParser, allocator: std.mem.Allocator) ![]Service {
        return self.getComponents(Service, "service", allocator);
    }

    /// Get all broadcast receivers from the manifest
    pub fn getReceivers(self: *const AxmlParser, allocator: std.mem.Allocator) ![]Receiver {
        return self.getComponents(Receiver, "receiver", allocator);
    }

    /// Generic component extraction helper
    fn getComponents(self: *const AxmlParser, comptime T: type, element_name: []const u8, allocator: std.mem.Allocator) ![]T {
        // Count components first
        var count: usize = 0;
        for (self.elements) |*elem| {
            if (std.mem.eql(u8, elem.name, element_name)) {
                count += 1;
            }
        }

        if (count == 0) return &.{};

        var components = try allocator.alloc(T, count);
        var comp_idx: usize = 0;

        // Track current component and its intent filters
        var i: usize = 0;
        while (i < self.elements.len) : (i += 1) {
            const elem = &self.elements[i];

            if (std.mem.eql(u8, elem.name, element_name)) {
                const name = getAttributeFromElementFast(elem, "name") orelse "";
                const exported_str = getAttributeFromElementFast(elem, "exported");
                const enabled_str = getAttributeFromElementFast(elem, "enabled");

                const exported: ?bool = if (exported_str) |e|
                    (std.mem.eql(u8, e, "true") or std.mem.eql(u8, e, "1"))
                else
                    null;

                const enabled = if (enabled_str) |e|
                    (std.mem.eql(u8, e, "true") or std.mem.eql(u8, e, "1"))
                else
                    true; // Default is enabled

                // Count intent filters for this component
                const component_depth = elem.depth;
                var filter_count: usize = 0;
                var j = i + 1;
                while (j < self.elements.len) : (j += 1) {
                    const child = &self.elements[j];
                    if (child.depth <= component_depth) break;
                    if (std.mem.eql(u8, child.name, "intent-filter") and child.depth == component_depth + 1) {
                        filter_count += 1;
                    }
                }

                // Allocate and populate intent filters
                var intent_filters: []IntentFilter = &.{};
                if (filter_count > 0) {
                    intent_filters = try allocator.alloc(IntentFilter, filter_count);
                    var filter_idx: usize = 0;

                    j = i + 1;
                    while (j < self.elements.len) : (j += 1) {
                        const child = &self.elements[j];
                        if (child.depth <= component_depth) break;

                        if (std.mem.eql(u8, child.name, "intent-filter") and child.depth == component_depth + 1) {
                            const filter_depth = child.depth;

                            // Count actions, categories, and data schemes
                            var action_count: usize = 0;
                            var category_count: usize = 0;
                            var data_count: usize = 0;

                            var k = j + 1;
                            while (k < self.elements.len) : (k += 1) {
                                const filter_child = &self.elements[k];
                                if (filter_child.depth <= filter_depth) break;

                                if (std.mem.eql(u8, filter_child.name, "action")) {
                                    action_count += 1;
                                } else if (std.mem.eql(u8, filter_child.name, "category")) {
                                    category_count += 1;
                                } else if (std.mem.eql(u8, filter_child.name, "data")) {
                                    if (getAttributeFromElementFast(filter_child, "scheme") != null) {
                                        data_count += 1;
                                    }
                                }
                            }

                            // Allocate arrays
                            var actions: [][]const u8 = &.{};
                            var categories: [][]const u8 = &.{};
                            var data_schemes: [][]const u8 = &.{};

                            if (action_count > 0) {
                                actions = try allocator.alloc([]const u8, action_count);
                            }
                            if (category_count > 0) {
                                categories = try allocator.alloc([]const u8, category_count);
                            }
                            if (data_count > 0) {
                                data_schemes = try allocator.alloc([]const u8, data_count);
                            }

                            // Populate arrays
                            var act_idx: usize = 0;
                            var cat_idx: usize = 0;
                            var data_idx: usize = 0;

                            k = j + 1;
                            while (k < self.elements.len) : (k += 1) {
                                const filter_child = &self.elements[k];
                                if (filter_child.depth <= filter_depth) break;

                                if (std.mem.eql(u8, filter_child.name, "action")) {
                                    if (getAttributeFromElementFast(filter_child, "name")) |action_name| {
                                        actions[act_idx] = action_name;
                                        act_idx += 1;
                                    }
                                } else if (std.mem.eql(u8, filter_child.name, "category")) {
                                    if (getAttributeFromElementFast(filter_child, "name")) |cat_name| {
                                        categories[cat_idx] = cat_name;
                                        cat_idx += 1;
                                    }
                                } else if (std.mem.eql(u8, filter_child.name, "data")) {
                                    if (getAttributeFromElementFast(filter_child, "scheme")) |scheme| {
                                        data_schemes[data_idx] = scheme;
                                        data_idx += 1;
                                    }
                                }
                            }

                            intent_filters[filter_idx] = .{
                                .actions = actions[0..act_idx],
                                .categories = categories[0..cat_idx],
                                .data_schemes = data_schemes[0..data_idx],
                            };
                            filter_idx += 1;
                        }
                    }
                    intent_filters = intent_filters[0..filter_idx];
                }

                components[comp_idx] = .{
                    .name = name,
                    .exported = exported,
                    .enabled = enabled,
                    .intent_filters = intent_filters,
                };
                comp_idx += 1;
            }
        }

        return components[0..comp_idx];
    }

    /// Get the install location from the manifest
    pub fn getInstallLocation(self: *const AxmlParser) InstallLocation {
        const manifest = self.findElement("manifest") orelse return .auto;
        const loc_str = getAttributeFromElementFast(manifest, "installLocation") orelse return .auto;
        return InstallLocation.fromString(loc_str);
    }

    /// Check if the application is debuggable
    pub fn isDebuggable(self: *const AxmlParser) bool {
        const app = self.findElement("application") orelse return false;
        const dbg_str = getAttributeFromElementFast(app, "debuggable") orelse return false;
        return std.mem.eql(u8, dbg_str, "true") or std.mem.eql(u8, dbg_str, "1");
    }

    /// Get the application label (app name)
    pub fn getAppLabel(self: *const AxmlParser) ?[]const u8 {
        const app = self.findElement("application") orelse return null;
        return getAttributeFromElementFast(app, "label");
    }

    /// Get the package name
    pub fn getPackageName(self: *const AxmlParser) ?[]const u8 {
        const manifest = self.findElement("manifest") orelse return null;
        return getAttributeFromElementFast(manifest, "package");
    }

    /// Get the version code
    pub fn getVersionCode(self: *const AxmlParser) ?[]const u8 {
        const manifest = self.findElement("manifest") orelse return null;
        return getAttributeFromElementFast(manifest, "versionCode");
    }

    /// Get the version name
    pub fn getVersionName(self: *const AxmlParser) ?[]const u8 {
        const manifest = self.findElement("manifest") orelse return null;
        return getAttributeFromElementFast(manifest, "versionName");
    }

    /// Get the minimum SDK version
    pub fn getMinSdkVersion(self: *const AxmlParser) ?u32 {
        const uses_sdk = self.findElement("uses-sdk") orelse return null;
        const min_sdk_str = getAttributeFromElementFast(uses_sdk, "minSdkVersion") orelse return null;
        return std.fmt.parseInt(u32, min_sdk_str, 10) catch null;
    }

    /// Get the target SDK version
    pub fn getTargetSdkVersion(self: *const AxmlParser) ?u32 {
        const uses_sdk = self.findElement("uses-sdk") orelse return null;
        const target_sdk_str = getAttributeFromElementFast(uses_sdk, "targetSdkVersion") orelse return null;
        return std.fmt.parseInt(u32, target_sdk_str, 10) catch null;
    }
};

/// Get attribute value from element - optimized with SIMD string comparison
inline fn getAttributeFromElementFast(elem: *const AxmlParser.XmlElement, attr_name: []const u8) ?[]const u8 {
    // Handle android: namespace prefix - compute once
    const search_name = if (attr_name.len > 8 and std.mem.eql(u8, attr_name[0..8], "android:"))
        attr_name[8..]
    else
        attr_name;

    // Linear search with SIMD-optimized string comparison
    for (elem.attributes) |*attr| {
        if (attr.name.len == search_name.len and SimdString.equals(attr.name, search_name)) {
            return attr.value;
        }
    }
    return null;
}

// Keep original function for API compatibility
fn getAttributeFromElement(elem: *const AxmlParser.XmlElement, attr_name: []const u8) ?[]const u8 {
    return getAttributeFromElementFast(elem, attr_name);
}

/// Optimized string pool parsing with pre-allocation
fn parseStringPoolOptimized(
    allocator: std.mem.Allocator,
    data: []const u8,
    pool: *std.ArrayListUnmanaged([]const u8),
) AxmlParser.AxmlError!void {
    if (data.len < 28) {
        @branchHint(.cold);
        return AxmlParser.AxmlError.InvalidStringPool;
    }

    const header_size = std.mem.readInt(u16, data[2..4], .little);
    const string_count = std.mem.readInt(u32, data[8..12], .little);
    const flags = std.mem.readInt(u32, data[16..20], .little);
    const strings_start = std.mem.readInt(u32, data[20..24], .little);
    const is_utf8 = (flags & 0x100) != 0;

    if (strings_start >= data.len) {
        @branchHint(.cold);
        return AxmlParser.AxmlError.InvalidStringPool;
    }

    const offsets_start: usize = header_size;
    const offsets_end = offsets_start + string_count * 4;
    if (offsets_end > data.len) {
        @branchHint(.cold);
        return AxmlParser.AxmlError.InvalidStringPool;
    }

    // Pre-allocate for all strings
    try pool.ensureTotalCapacity(allocator, pool.items.len + string_count);

    // Batch process string offsets
    var i: u32 = 0;
    while (i < string_count) : (i += 1) {
        const offset_pos = offsets_start + i * 4;
        if (offset_pos + 4 > data.len) break;

        const string_offset = std.mem.readInt(u32, data[offset_pos..][0..4], .little);
        const abs_offset = strings_start + string_offset;

        if (abs_offset >= data.len) {
            pool.appendAssumeCapacity(try allocator.dupe(u8, ""));
            continue;
        }

        const remaining_data = data[abs_offset..];
        const str = if (is_utf8)
            parseUtf8StringFast(remaining_data)
        else
            parseUtf16ToUtf8(allocator, remaining_data) catch "";

        // For UTF-8, we need to dupe; for UTF-16, it's already allocated
        const final_str = if (is_utf8)
            try allocator.dupe(u8, str)
        else
            str;

        pool.appendAssumeCapacity(final_str);
    }
}

/// Parse UTF-8 string - optimized inline version
inline fn parseUtf8StringFast(data: []const u8) []const u8 {
    if (data.len < 2) return "";

    var offset: usize = 0;

    // Skip character count (1 or 2 bytes)
    if (data[0] & 0x80 != 0) {
        if (data.len < 2) return "";
        offset = 2;
    } else {
        offset = 1;
    }

    if (offset >= data.len) return "";

    // Read byte length
    var byte_len: usize = undefined;
    if (data[offset] & 0x80 != 0) {
        if (offset + 2 > data.len) return "";
        byte_len = (@as(usize, data[offset] & 0x7F) << 8) | @as(usize, data[offset + 1]);
        offset += 2;
    } else {
        byte_len = data[offset];
        offset += 1;
    }

    if (byte_len == 0) return "";
    if (offset + byte_len > data.len) {
        byte_len = data.len - offset;
    }

    // Find null terminator using optimized scan
    const string_data = data[offset..];
    const max_len = @min(byte_len, string_data.len);

    // Use std.mem.indexOfScalar for potentially vectorized search
    const null_pos = std.mem.indexOfScalar(u8, string_data[0..max_len], 0);
    const actual_len = null_pos orelse max_len;

    return string_data[0..actual_len];
}

/// Parse UTF-16 to UTF-8 with direct allocation (no static buffer)
fn parseUtf16ToUtf8(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    if (data.len < 2) return "";

    const char_count = std.mem.readInt(u16, data[0..2], .little);
    if (char_count == 0) return "";

    // Allocate worst case: 4 bytes per UTF-16 code unit
    var buffer = try allocator.alloc(u8, @as(usize, char_count) * 4);
    errdefer allocator.free(buffer);

    var out_idx: usize = 0;
    var in_idx: usize = 2;
    var chars_read: u16 = 0;

    while (chars_read < char_count and in_idx + 1 < data.len) {
        const code_unit = std.mem.readInt(u16, data[in_idx..][0..2], .little);
        in_idx += 2;

        if (code_unit == 0) break;

        // Handle surrogate pairs
        if (code_unit >= 0xD800 and code_unit <= 0xDBFF) {
            if (in_idx + 1 < data.len) {
                const low_surrogate = std.mem.readInt(u16, data[in_idx..][0..2], .little);
                if (low_surrogate >= 0xDC00 and low_surrogate <= 0xDFFF) {
                    in_idx += 2;
                    chars_read += 1;
                    const code_point: u21 = 0x10000 + ((@as(u21, code_unit - 0xD800) << 10) | @as(u21, low_surrogate - 0xDC00));
                    buffer[out_idx] = @intCast(0xF0 | (code_point >> 18));
                    buffer[out_idx + 1] = @intCast(0x80 | ((code_point >> 12) & 0x3F));
                    buffer[out_idx + 2] = @intCast(0x80 | ((code_point >> 6) & 0x3F));
                    buffer[out_idx + 3] = @intCast(0x80 | (code_point & 0x3F));
                    out_idx += 4;
                }
            }
        } else if (code_unit < 0x80) {
            buffer[out_idx] = @intCast(code_unit);
            out_idx += 1;
        } else if (code_unit < 0x800) {
            buffer[out_idx] = @intCast(0xC0 | (code_unit >> 6));
            buffer[out_idx + 1] = @intCast(0x80 | (code_unit & 0x3F));
            out_idx += 2;
        } else {
            buffer[out_idx] = @intCast(0xE0 | (code_unit >> 12));
            buffer[out_idx + 1] = @intCast(0x80 | ((code_unit >> 6) & 0x3F));
            buffer[out_idx + 2] = @intCast(0x80 | (code_unit & 0x3F));
            out_idx += 3;
        }

        chars_read += 1;
    }

    // Shrink to actual size
    if (out_idx < buffer.len) {
        return allocator.realloc(buffer, out_idx) catch buffer[0..out_idx];
    }
    return buffer[0..out_idx];
}

/// Optimized start element parsing
fn parseStartElementOptimized(
    allocator: std.mem.Allocator,
    data: []const u8,
    string_pool: []const []const u8,
    depth: u32,
) AxmlParser.AxmlError!AxmlParser.XmlElement {
    if (data.len < 36) {
        @branchHint(.cold);
        return AxmlParser.AxmlError.TruncatedData;
    }

    const ns_idx = std.mem.readInt(u32, data[16..20], .little);
    const name_idx = std.mem.readInt(u32, data[20..24], .little);
    const attr_count = std.mem.readInt(u16, data[28..30], .little);

    const namespace = if (ns_idx < string_pool.len and ns_idx != 0xFFFFFFFF)
        string_pool[ns_idx]
    else
        "";

    const name = if (name_idx < string_pool.len)
        string_pool[name_idx]
    else
        "";

    // Pre-allocate exact attribute count
    var attributes = try allocator.alloc(AxmlParser.XmlAttribute, attr_count);
    var attr_idx: usize = 0;

    var attr_offset: usize = 36;
    var i: u16 = 0;
    while (i < attr_count) : (i += 1) {
        if (attr_offset + 20 > data.len) break;

        const attr_ns_idx = std.mem.readInt(u32, data[attr_offset..][0..4], .little);
        const attr_name_idx = std.mem.readInt(u32, data[attr_offset + 4 ..][0..4], .little);
        const attr_raw_value_idx = std.mem.readInt(u32, data[attr_offset + 8 ..][0..4], .little);
        const attr_type = data[attr_offset + 15];
        const attr_data = std.mem.readInt(u32, data[attr_offset + 16 ..][0..4], .little);

        const attr_ns = if (attr_ns_idx < string_pool.len and attr_ns_idx != 0xFFFFFFFF)
            string_pool[attr_ns_idx]
        else
            "";

        const attr_name = if (attr_name_idx < string_pool.len)
            string_pool[attr_name_idx]
        else
            "";

        const attr_value = blk: {
            if (attr_type == 0x03) {
                if (attr_raw_value_idx < string_pool.len and attr_raw_value_idx != 0xFFFFFFFF) {
                    break :blk string_pool[attr_raw_value_idx];
                }
            }
            break :blk formatIntValueFast(allocator, attr_data, attr_type) catch "";
        };

        attributes[attr_idx] = .{
            .name = attr_name,
            .namespace = attr_ns,
            .value = attr_value,
            .value_type = @enumFromInt(attr_type),
        };
        attr_idx += 1;
        attr_offset += 20;
    }

    return AxmlParser.XmlElement{
        .name = name,
        .namespace = namespace,
        .attributes = attributes[0..attr_idx],
        .depth = depth,
    };
}

/// Format integer value - optimized with smaller buffer
fn formatIntValueFast(allocator: std.mem.Allocator, value: u32, value_type: u8) ![]const u8 {
    return switch (value_type) {
        0x12 => if (value != 0) "true" else "false", // Boolean - no allocation
        0x10 => blk: { // Decimal
            var buf: [11]u8 = undefined; // Max u32 is 10 digits + sign
            const str = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return "";
            break :blk try allocator.dupe(u8, str);
        },
        0x11 => blk: { // Hex
            var buf: [10]u8 = undefined; // "0x" + 8 hex digits
            const str = std.fmt.bufPrint(&buf, "0x{x}", .{value}) catch return "";
            break :blk try allocator.dupe(u8, str);
        },
        else => blk: {
            var buf: [11]u8 = undefined;
            const str = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return "";
            break :blk try allocator.dupe(u8, str);
        },
    };
}

// ============================================================================
// Legacy API compatibility functions (for existing tests)
// ============================================================================

/// Parse string pool chunk - legacy wrapper for tests
fn parseStringPool(allocator: std.mem.Allocator, data: []const u8, pool: *std.ArrayListUnmanaged([]const u8)) AxmlParser.AxmlError!void {
    if (data.len < 28) {
        @branchHint(.cold);
        return AxmlParser.AxmlError.InvalidStringPool;
    }

    const header_size = std.mem.readInt(u16, data[2..4], .little);
    const string_count = std.mem.readInt(u32, data[8..12], .little);
    const flags = std.mem.readInt(u32, data[16..20], .little);
    const strings_start = std.mem.readInt(u32, data[20..24], .little);
    const is_utf8 = (flags & 0x100) != 0;

    if (strings_start >= data.len) {
        @branchHint(.cold);
        return AxmlParser.AxmlError.InvalidStringPool;
    }

    const offsets_start: usize = header_size;
    const offsets_end = offsets_start + string_count * 4;
    if (offsets_end > data.len) {
        @branchHint(.cold);
        return AxmlParser.AxmlError.InvalidStringPool;
    }

    // Pre-allocate for all strings
    pool.ensureTotalCapacity(allocator, pool.items.len + string_count) catch return AxmlParser.AxmlError.OutOfMemory;

    var i: u32 = 0;
    while (i < string_count) : (i += 1) {
        const offset_pos = offsets_start + i * 4;
        if (offset_pos + 4 > data.len) break;

        const string_offset = std.mem.readInt(u32, data[offset_pos..][0..4], .little);
        const abs_offset = strings_start + string_offset;

        if (abs_offset >= data.len) {
            pool.appendAssumeCapacity(allocator.dupe(u8, "") catch return AxmlParser.AxmlError.OutOfMemory);
            continue;
        }

        const remaining_data = data[abs_offset..];
        const str = if (is_utf8)
            parseUtf8StringFast(remaining_data)
        else
            parseUtf16StringFixed(remaining_data);

        pool.appendAssumeCapacity(allocator.dupe(u8, str) catch return AxmlParser.AxmlError.OutOfMemory);
    }
}

/// Parse UTF-8 string from AXML (original implementation for tests)
fn parseUtf8String(data: []const u8) []const u8 {
    return parseUtf8StringFast(data);
}

/// Parse UTF-8 string - Fixed implementation (alias)
fn parseUtf8StringFixed(data: []const u8) []const u8 {
    return parseUtf8StringFast(data);
}

/// Parse UTF-16 string from AXML (legacy - uses static buffer for compatibility)
fn parseUtf16String(data: []const u8) []const u8 {
    return parseUtf16StringFixed(data);
}

/// Parse UTF-16 string - Fixed implementation with static buffer
fn parseUtf16StringFixed(data: []const u8) []const u8 {
    if (data.len < 2) return "";

    const char_count = std.mem.readInt(u16, data[0..2], .little);
    if (char_count == 0) return "";

    const S = struct {
        var buffer: [8192]u8 = undefined;
    };

    var out_idx: usize = 0;
    var in_idx: usize = 2;
    var chars_read: u16 = 0;

    while (chars_read < char_count and in_idx + 1 < data.len and out_idx < S.buffer.len - 4) {
        const code_unit = std.mem.readInt(u16, data[in_idx..][0..2], .little);
        in_idx += 2;

        if (code_unit == 0) break;

        if (code_unit >= 0xD800 and code_unit <= 0xDBFF) {
            if (in_idx + 1 < data.len) {
                const low_surrogate = std.mem.readInt(u16, data[in_idx..][0..2], .little);
                if (low_surrogate >= 0xDC00 and low_surrogate <= 0xDFFF) {
                    in_idx += 2;
                    chars_read += 1;
                    const code_point: u21 = 0x10000 + ((@as(u21, code_unit - 0xD800) << 10) | @as(u21, low_surrogate - 0xDC00));
                    S.buffer[out_idx] = @intCast(0xF0 | (code_point >> 18));
                    S.buffer[out_idx + 1] = @intCast(0x80 | ((code_point >> 12) & 0x3F));
                    S.buffer[out_idx + 2] = @intCast(0x80 | ((code_point >> 6) & 0x3F));
                    S.buffer[out_idx + 3] = @intCast(0x80 | (code_point & 0x3F));
                    out_idx += 4;
                }
            }
        } else if (code_unit < 0x80) {
            S.buffer[out_idx] = @intCast(code_unit);
            out_idx += 1;
        } else if (code_unit < 0x800) {
            S.buffer[out_idx] = @intCast(0xC0 | (code_unit >> 6));
            S.buffer[out_idx + 1] = @intCast(0x80 | (code_unit & 0x3F));
            out_idx += 2;
        } else {
            S.buffer[out_idx] = @intCast(0xE0 | (code_unit >> 12));
            S.buffer[out_idx + 1] = @intCast(0x80 | ((code_unit >> 6) & 0x3F));
            S.buffer[out_idx + 2] = @intCast(0x80 | (code_unit & 0x3F));
            out_idx += 3;
        }

        chars_read += 1;
    }

    return S.buffer[0..out_idx];
}

/// Parse start element chunk - legacy wrapper
fn parseStartElement(
    allocator: std.mem.Allocator,
    data: []const u8,
    string_pool: []const []const u8,
    depth: u32,
) AxmlParser.AxmlError!AxmlParser.XmlElement {
    return parseStartElementOptimized(allocator, data, string_pool, depth);
}

/// Format integer value as string - legacy wrapper
fn formatIntValue(allocator: std.mem.Allocator, value: u32, value_type: u8) ![]const u8 {
    return formatIntValueFast(allocator, value, value_type);
}

// ============================================================================
// Unit Tests
// ============================================================================

test "AxmlParser basic structure" {
    const attr = AxmlParser.XmlAttribute{
        .name = "package",
        .namespace = "android",
        .value = "com.example.app",
        .value_type = .string,
    };
    try std.testing.expectEqualStrings("package", attr.name);
    try std.testing.expectEqualStrings("com.example.app", attr.value);
}

test "AxmlParser ValueType enum" {
    try std.testing.expectEqual(AxmlParser.ValueType.string, @as(AxmlParser.ValueType, @enumFromInt(0x03)));
    try std.testing.expectEqual(AxmlParser.ValueType.int_dec, @as(AxmlParser.ValueType, @enumFromInt(0x10)));
    try std.testing.expectEqual(AxmlParser.ValueType.int_boolean, @as(AxmlParser.ValueType, @enumFromInt(0x12)));
}

test "parseUtf8String empty" {
    const result = parseUtf8String("");
    try std.testing.expectEqualStrings("", result);
}

test "parseUtf8String with simple ASCII" {
    const utf8_data = [_]u8{
        11, // char count: 11
        11, // byte length: 11
        'c',
        'o',
        'm',
        '.',
        'e',
        'x',
        'a',
        'm',
        'p',
        'l',
        'e',
        0, // null terminator
    };

    const result = parseUtf8String(&utf8_data);
    try std.testing.expectEqualStrings("com.example", result);
}

test "parseUtf8String with 2-byte length" {
    const utf8_data = [_]u8{
        0x80 | 0, 5, // char count: 5 (2-byte format)
        5, // byte length: 5
        'h',
        'e',
        'l',
        'l',
        'o',
        0, // null terminator
    };

    const result = parseUtf8String(&utf8_data);
    try std.testing.expectEqualStrings("hello", result);
}

test "getAttributeFromElement with android prefix" {
    const attrs = [_]AxmlParser.XmlAttribute{
        .{
            .name = "versionCode",
            .namespace = "android",
            .value = "1",
            .value_type = .int_dec,
        },
    };

    const elem = AxmlParser.XmlElement{
        .name = "manifest",
        .namespace = "",
        .attributes = &attrs,
        .depth = 0,
    };

    const result = getAttributeFromElement(&elem, "android:versionCode");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("1", result.?);

    const result2 = getAttributeFromElement(&elem, "versionCode");
    try std.testing.expect(result2 != null);
    try std.testing.expectEqualStrings("1", result2.?);
}

test "parseUtf16String with ASCII" {
    const utf16_data = [_]u8{
        0x0B, 0x00, // Length: 11 characters
        0x63, 0x00, // 'c'
        0x6F, 0x00, // 'o'
        0x6D, 0x00, // 'm'
        0x2E, 0x00, // '.'
        0x65, 0x00, // 'e'
        0x78, 0x00, // 'x'
        0x61, 0x00, // 'a'
        0x6D, 0x00, // 'm'
        0x70, 0x00, // 'p'
        0x6C, 0x00, // 'l'
        0x65, 0x00, // 'e'
    };

    const result = parseUtf16String(&utf16_data);
    try std.testing.expectEqualStrings("com.example", result);
}

test "parseUtf16String with non-ASCII" {
    const utf16_data = [_]u8{
        0x04, 0x00, // Length: 4 characters
        0x54, 0x00, // 'T'
        0xEB, 0x00, // 'ë' (U+00EB)
        0x73, 0x00, // 's'
        0x74, 0x00, // 't'
    };

    const result = parseUtf16String(&utf16_data);
    try std.testing.expectEqualStrings("T\xC3\xABst", result);
}

test "parseUtf16String empty" {
    const utf16_data = [_]u8{ 0x00, 0x00 };
    const result = parseUtf16String(&utf16_data);
    try std.testing.expectEqualStrings("", result);
}

test "parseStringPool with UTF-8 strings" {
    const allocator = std.testing.allocator;

    var chunk: [65]u8 = undefined;

    // Header
    std.mem.writeInt(u16, chunk[0..2], 0x0001, .little);
    std.mem.writeInt(u16, chunk[2..4], 28, .little);
    std.mem.writeInt(u32, chunk[4..8], 65, .little);
    std.mem.writeInt(u32, chunk[8..12], 2, .little);
    std.mem.writeInt(u32, chunk[12..16], 0, .little);
    std.mem.writeInt(u32, chunk[16..20], 0x100, .little);
    std.mem.writeInt(u32, chunk[20..24], 36, .little);
    std.mem.writeInt(u32, chunk[24..28], 0, .little);

    // String offsets
    std.mem.writeInt(u32, chunk[28..32], 0, .little);
    std.mem.writeInt(u32, chunk[32..36], 11, .little);

    // String 0: "manifest"
    chunk[36] = 8;
    chunk[37] = 8;
    @memcpy(chunk[38..46], "manifest");
    chunk[46] = 0;

    // String 1: "com.example.app"
    chunk[47] = 15;
    chunk[48] = 15;
    @memcpy(chunk[49..64], "com.example.app");
    chunk[64] = 0;

    var pool = std.ArrayListUnmanaged([]const u8){};
    defer {
        for (pool.items) |s| {
            allocator.free(s);
        }
        pool.deinit(allocator);
    }

    try parseStringPool(allocator, &chunk, &pool);

    try std.testing.expectEqual(@as(usize, 2), pool.items.len);
    try std.testing.expectEqualStrings("manifest", pool.items[0]);
    try std.testing.expectEqualStrings("com.example.app", pool.items[1]);
}
