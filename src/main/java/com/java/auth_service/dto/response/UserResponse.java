package com.java.auth_service.dto.response;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;

import com.java.auth_service.entity.Role;
import com.java.auth_service.entity.User;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserResponse {
    String id;
    String username;
    String firstName;
    String lastName;
    LocalDate dob;
    Set<RoleResponse> roles;

    public static UserResponse convertFromUser(User user) {
        Set<Role> roles = user.getRoles();
        Set<RoleResponse> roleResponses = new HashSet<>();

        if (!roles.isEmpty())
            roles.forEach(role -> {
                RoleResponse roleResponse = RoleResponse.from(role);
                roleResponses.add(roleResponse);
            });

        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .dob(user.getDob())
                .roles(roleResponses)
                .build();
    }
}
