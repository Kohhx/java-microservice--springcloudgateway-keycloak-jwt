package com.kohhx.gatewayservice.DTO;

public class InstrospectResponseDTO {
    private Boolean active;

    public InstrospectResponseDTO() {
    }

    public InstrospectResponseDTO(Boolean active) {
        this.active = active;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }
}
