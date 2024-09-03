package com.java.auth_service.entity;

import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Entity // Lưu những token mà người dùng đã đăng xuất
public class InvalidatedToken {
    @Id
    String id;

    // Thời gian hết hạn của token
    Date expiryTime;
}
