package com.example.security.request;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class VerificactionRequest {
    private String email;
    private String code;
}
