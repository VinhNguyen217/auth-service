package com.java.auth_service.service;

import java.util.HashSet;
import java.util.List;

import com.java.auth_service.dto.request.RoleRequest;
import com.java.auth_service.dto.response.RoleResponse;
import com.java.auth_service.entity.Role;
import com.java.auth_service.repo.PermissionRepository;
import com.java.auth_service.repo.RoleRepository;
import org.springframework.stereotype.Service;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class RoleService {
    RoleRepository roleRepository;
    PermissionRepository permissionRepository;

    public RoleResponse create(RoleRequest request) {
        Role role = Role.builder()
                .name(request.getName())
                .build();

        var permissions = permissionRepository.findAllById(request.getPermissions());
        role.setPermissions(new HashSet<>(permissions));

        role = roleRepository.save(role);
        return RoleResponse.from(role);
    }

    public List<RoleResponse> getAll() {
        return roleRepository.findAll().stream().map(RoleResponse::from).toList();
    }

    public void delete(String role) {
        roleRepository.deleteById(role);
    }
}
