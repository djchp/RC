
# Create asset-vulnerability pairs from 3 JSON files

Assumptions I made:
- we need to create asset-vulnerability pairs where any vulnerability versions overlaps with one of the assets version for given platform id.

My solution described:
- data validation using ajv
- reading and writing files using streams
- semantic versioning achieved using node package compare-version
- creating interval-trees with node-interval-trees package

My solution doesn't contain parallel processing i tried to implement it but it would be tricky because i you can only send serializable data structures between workers and my initial approach was to split larger file from assets and vulnerabilities and process does chunks in parallel and i think preprocessing assets with platforms and iserting them into interval-trees might solve the bottlnecks that might happen in this application, what i really paid attention was the case when we have really small amount of platforms(i did 10) and a big assets and vulnerabilities files(i did 10000) where each one of them has 3 realtions to one of the 10 platforms so if all versions overlap for this case we need to produce the output of 10000 * 3 * 10000 * 3 which equal 900000 asset-vulnerability pairs. So i think the solution may vary depending of the data specifications how much platforms we have etc

# To run project

```
npm install
```

and then if you want to test data validation modify env file according to instructions given there so for example uncomment test files paths and run 
```
npm run test
```
and if you want to run script with real world case scenario files uncomment paths for them in env and simply run npm run start, scripts provided in package.json will take care of the rest
