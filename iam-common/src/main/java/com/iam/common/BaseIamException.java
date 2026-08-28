package com.iam.common;

public class BaseIamException extends RuntimeException{
    private final String errorCode;
    private final int status;
    protected BaseIamException(String message, String errorCode, int status){
        super(message);
        this.errorCode=errorCode;
        this.status=status;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public int getStatus() {
        return status;
    }
}
