import { Component } from '@angular/core';
import { Login } from "./models/login";
import { Register } from "./models/register";
import { JwtAuth } from "./models/jwtAuth";
import { AuthenticationService } from "./services/authentication.service";

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'Drivers.App';
  loginDto = new Login();
  registerDto = new Register();
  jwtDto = new JwtAuth();

  constructor(private authService: AuthenticationService){}

  Register(registerDto: Register){
    this.authService.register(registerDto).subscribe();
  }

  Login(loginDto: Login){
    this.authService.login(loginDto).subscribe((jwtDto) => {
      localStorage.setItem('jwtToken', jwtDto.token);
    });
  }

  Weather(){
    this.authService.getWeather().subscribe((weatherData: any) => {
      console.log(weatherData);
    });
  }
}
