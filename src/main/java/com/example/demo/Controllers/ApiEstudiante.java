package com.example.demo.Controllers;


import com.example.demo.model.Estudiante;
import com.example.demo.repository.EstudianteRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController()
@RequestMapping("rest")
public class ApiEstudiante {
    @Autowired
    EstudianteRepository estudianteRepository;
    @GetMapping("/saludar")
    public String saludar(){
        return "Hola mundo";
    }
    @GetMapping("/")
    public String index(){
        return "index";
    }
    @GetMapping("/all")
    public List<Estudiante> getEstudiante(){
        return estudianteRepository.findAll();
    }

    @PostMapping("/save/{cedula}")
    public Estudiante addEstudiante(@PathVariable String cedula,@RequestBody Estudiante estudiante){
        estudiante.setCedula(cedula);
        return estudianteRepository.saveAndFlush(estudiante);
    }
    @PutMapping("/edit/{cedula}")
    public Estudiante editEstudiante(@PathVariable String cedula ,@RequestBody Estudiante estudiante){
        estudiante.setCedula(cedula);
        return estudianteRepository.saveAndFlush(estudiante);
    }
    @DeleteMapping("/delete/{cedula}")
    public void deleteEstudiante(@PathVariable String cedula){
        estudianteRepository.deleteById(cedula);
    }

    @GetMapping("/get/{cedula}")
public Estudiante getEstudianteByID(@PathVariable String cedula) {
    return estudianteRepository.findById(cedula);}

}
