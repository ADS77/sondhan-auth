package com.sondhan.auth.dto.response;

import com.sondhan.auth.dto.AuthDtos;

public record ApiResponse<T>(T data) {
    public static <T> ApiResponse<T> of(T data) {
        return new ApiResponse(data);
    }

}
