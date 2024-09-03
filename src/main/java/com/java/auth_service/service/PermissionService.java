package com.java.auth_service.service;

import java.util.List;

import com.java.auth_service.dto.request.PermissionRequest;
import com.java.auth_service.dto.response.PermissionResponse;
import com.java.auth_service.entity.Permission;
import com.java.auth_service.repo.PermissionRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class PermissionService {
    PermissionRepository permissionRepository;

//    @PreAuthorize("hasRole('ADMIN')")
    public PermissionResponse create(PermissionRequest request) {
        Permission permission = Permission.builder()
                .name(request.getName())
                .build();
        permission = permissionRepository.save(permission);
        return PermissionResponse.from(permission);
    }

//    @PreAuthorize("hasRole('ADMIN')")
    public List<PermissionResponse> getAll() {
        var permissions = permissionRepository.findAll();
        return permissions.stream().map(PermissionResponse::from).toList();
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void delete(String permission) {
        permissionRepository.deleteById(permission);
    }
}
