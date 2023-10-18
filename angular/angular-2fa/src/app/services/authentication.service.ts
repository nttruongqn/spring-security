import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { RegisterRequest } from '../models/register-request';
import { Observable } from 'rxjs';
import { AuthenticationResponse } from '../models/authentication-response';
import { VerificationRequest } from '../models/verification-request';
import { AuthenticationRequest } from '../models/authentication-request';

@Injectable({
  providedIn: 'root'
})
export class AuthenticationService {

  private baseUrl:string = 'http://localhost:4141/api/v1/auth'

  constructor(
    private http: HttpClient
  ) { }

  register(registeRequest: RegisterRequest): Observable<AuthenticationResponse> {
    return this.http.post<AuthenticationResponse>(`${this.baseUrl}/register`, registeRequest);
  }

  verifyCode(verificationRequest: VerificationRequest): Observable<AuthenticationResponse> {
    return this.http.post<AuthenticationResponse>(`${this.baseUrl}/verify`, verificationRequest);
  }

  login(
    authRequest: AuthenticationRequest
  ) {
    return this.http.post<AuthenticationResponse>
    (`${this.baseUrl}/login`, authRequest);
  }

}
