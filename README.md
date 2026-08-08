# Home SOC Lab

Proyecto personal creado desde cero para practicar habilidades de **SOC Analyst**, utilizando un entorno de laboratorio con Windows, Sysmon y Splunk.

## Objetivo

Simulé actividad maliciosa en un entorno controlado, recopilar los eventos con Sysmon y analizarlos en Splunk para practicar detección e investigación de amenazas.

## Herramientas

* Splunk Enterprise
* Splunk Universal Forwarder
* Sysmon
* Windows 11
* VirtualBox
* MITRE ATT&CK

## Primera investigación

**Credential Dumping con Mimikatz**

Se simuló la ejecución de Mimikatz y posteriormente se analizaron los eventos generados en Splunk, identificando procesos, usuarios, hashes e indicadores relevantes.

La actividad fue relacionada con:

**MITRE ATT&CK T1003.001 — LSASS Memory**

También se configuró una alerta en Splunk para detectar este tipo de actividad.

📄 [Ver reporte completo](./Reporte-Mimikatz-Credential-Dumping.md)

