package com.java.auth_service.dto.response;

import java.util.HashSet;
import java.util.Set;

import com.java.auth_service.entity.Permission;
import com.java.auth_service.entity.Role;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RoleResponse {
    String name;
    Set<PermissionResponse> permissions;

    public static RoleResponse from(Role role) {
        Set<Permission> permissions = role.getPermissions();
        Set<PermissionResponse> permissionResponses = new HashSet<>();

        if (!permissions.isEmpty())
            permissions.forEach(permission -> permissionResponses.add(PermissionResponse.from(permission)));

        return RoleResponse.builder()
                .name(role.getName())
                .permissions(permissionResponses)
                .build();
    }
}
