package com.java.auth_service.dto.response;

import com.java.auth_service.entity.Permission;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class PermissionResponse {
    String name;

    public static PermissionResponse from(Permission permission) {
        return PermissionResponse.builder()
                .name(permission.getName())
                .build();
    }
}
