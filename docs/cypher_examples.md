# Prophet Knowledge Graph: Cypher Queries

Este documento contiene consultas útiles de Neo4j para explotar el Knowledge Graph construido a partir de alertas de Wazuh enriquecidas con STIX y MITRE ATT&CK.

## 1. Blast Radius de una Técnica Mitre (Radio de Explosión)

Esta consulta responde a la pregunta inmediata de los analistas: **"Se detectó la técnica T1059. ¿Cuáles son todos los Host, Usuarios e IPs que podrían estar comprometidos o involucrados con esta técnica?"**

```cypher
MATCH (t:Technique {technique_id: 'T1059'})<-[:INDICATES]-(e:Event)-[:OCCURRED_ON]->(h:Host)
OPTIONAL MATCH (u:User)-[:TRIGGERED]->(e)
OPTIONAL MATCH (e)<-[:INITIATED]-(src:IP)
RETURN t.technique_id AS Technique,
       h.hostname AS Affected_Host,
       collect(DISTINCT u.username) AS Involved_Users,
       collect(DISTINCT src.address) AS Source_IPs,
       count(e) AS Total_Events
ORDER BY Total_Events DESC
```

## 2. Visibilidad completa de un Incidente (Conexiones entre hosts)

Evalúa si un atacante usando una misma técnica se está moviendo lateralmente (ej. T1021 - Lateral Tool Transfer).

```cypher
MATCH path = (src:IP)-[:INITIATED]->(e:Event)-[:INDICATES]->(t:Technique {technique_id: 'T1021'})
MATCH (e)-[:OCCURRED_ON]->(targetHost:Host)
RETURN path, src.address AS Attacker_IP, targetHost.hostname AS Target_Host
```

## 3. Top 5 Tácticas más explotadas en la Red

Calcula qué etapas de ataque (Tácticas) son las más frecuentes basadas en las reglas disparadas:

```cypher
MATCH (e:Event)-[:INDICATES]->(ta:Tactic)
RETURN ta.name AS Tactic_Name, count(e) AS Event_Count
ORDER BY Event_Count DESC
LIMIT 5
```

## 4. Usuarios con mayor cantidad de Alertas Críticas (Múltiples Técnicas)

Busca usuarios comprometidos interactuando con muchas técnicas diferentes:

```cypher
MATCH (u:User)-[:TRIGGERED]->(e:Event)-[:INDICATES]->(t:Technique)
RETURN u.username AS Username,
       count(DISTINCT t.technique_id) AS Distinct_Techniques_Used,
       collect(DISTINCT t.technique_id) AS Techniques
ORDER BY Distinct_Techniques_Used DESC
```

## 5. Origen Geográfico de Ataques Críticos

Visualiza los países desde donde se originan intentos de explotación mapeados en el Grafo de Conocimiento:

```cypher
MATCH (loc:Location)<-[:LOCATED_IN]-(src:IP)-[:INITIATED]->(e:Event)-[:INDICATES]->(t:Technique)
RETURN loc.country_name AS Attacker_Country,
       loc.city_name AS Attacker_City,
       count(e) AS Attempt_Count,
       collect(DISTINCT t.technique_id) AS Tactics_Used
ORDER BY Attempt_Count DESC
```

## 6. Recomendaciones de Mitigación Inmediata

Analiza una IP destino específica o Host y devuelve todas las mitigaciones sugeridas para los ataques que está recibiendo:

```cypher
MATCH (h:Host {hostname: 'srv-db-prod'})<-[:OCCURRED_ON]-(e:Event)-[:INDICATES]->(t:Technique)<-[:MITIGATES]-(m:Mitigation)
RETURN h.hostname AS Endpoint,
       t.technique_id AS Technique,
       m.mitigation_id AS Mitigation_Rule,
       m.description AS Remediation_Action
```
