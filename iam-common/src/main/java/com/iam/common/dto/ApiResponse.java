package com.iam.common.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T> (
        boolean success,
        String message,
        T data,
        String errorCode
) {
    public static <T> ApiResponse<T> success(T data, String message){
        return new ApiResponse<>(true, message, data, null);
    }
    public static <T> ApiResponse<T> error(String message, String errorCode){
        return new ApiResponse<>(false, message, null, errorCode);
    }
}
