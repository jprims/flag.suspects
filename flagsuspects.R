################################
### VSP & Geolocation Method ###
################################

  # Code by JP Prims

## Format: 
  # flag.suspects(Latitude, Longitude, IP)

## Arguments: 
  # Latitude: A column of latitudes. (Optional)
  # Longitude: A column of longitudes. (Optional)
  # IP: A column of IP addresses. (Optional)

  # You must enter either LATITUDE AND LONGITUDE or IP for the function to run. 

## Notes: 
  # If you enter ONLY LATITUDE AND LONGITUDE: 
    # The function returns a 1 if that latitude and longitude is suspicious, and a 0 if it is not. 

  # If you enter ONLY IP ADDRESS: 
    # The function returns a 1 if the IP address is from a suspicious ISP, and a 0 if it is not. 

flag.suspects <- function(Latitude, Longitude, IP, Octets = TRUE){
  
  # Makes sure that necessary packages are installed and loaded
  ifelse(!"ipapi" %in% installed.packages(), devtools::install_github("hrbrmstr/ipapi"), library(ipapi))
  require(maps)
  require(leaflet)
  ifelse(!"package:ipapi" %in% search(), library(ipapi), NA) # Only necessary if you're installing ipapi for the first time. 
  
  # Reading in list of suspicious locations
  urlfile <- 'https://raw.githubusercontent.com/jprims/flag.suspects/master/suspiciousthings.csv'
  datsus<-read.csv(urlfile)
  
  if(missing(Latitude)) {
    NULL
  } else {
    
    
    ##### Duplicate GPS coordinates #####
    # Creating empty vector
    bot.susp <- bot.susp <- rep(0, length(Latitude))
    
    # Creating an object combining those two into one column 
    latlong <- ifelse(!is.na(Latitude), paste(Latitude,Longitude), NA)
    
    
    # Creating a list of "bad" GPS locations
    badgps <- ifelse(!is.na(Latitude), paste(datsus$badlat, datsus$badlong), NA)
    
    # This checks if the coordinates are duplicated. If so, it adds a point. 
    bot.susp <- ifelse(!is.na(latlong), ifelse(latlong %in% badgps, bot.susp + 1,  bot.susp), bot.susp) 
    
  }
  
  #### ISP check ####
  # This part makes this argument optional for the function. 
  if(missing(IP)) {
    NULL
  } else {
    if(missing(Latitude)) {
      # Creating empty vector
      bot.susp <- bot.susp <- rep(0, length(IP))
    } else {
      NULL
    }
    
    # First, we need to deal with octets. 
    if(Octets == FALSE) {
      NULL
    } else {
      IP <- sub("\\.+$",".120",IP)
    }
    
    
    # I'd like to remove punctuation, and make all of the suspicious ISPs lowercase, just to make matches easier.
    vsps <- tolower(datsus$badas)
    vsps <- gsub("[[:punct:]]", "", vsps)
    
    # Now, let's get the isps. 
    locations <- geolocate(IP)
    
    # We're using the AS column, but not some ISPs have multiple ASs, wo we're removing that number
    locations$asc <- sub(".*? (.+)", "\\1", locations$as)
    vsps <- sub(".*? (.+)", "\\1", vsps)
    
    # Cleaning that up too, so it's lowercase, and missing punctuation. 
    locations$asc <- tolower(locations$asc)
    locations$asc <- gsub("[[:punct:]]", "", locations$asc)
    
    # Now, returning 1 or 0. 
    bot.susp <- ifelse(!is.na(locations$asc), ifelse(pmatch(locations$asc, vsps, nomatch = 0, duplicates.ok = TRUE) > 0, bot.susp + 1,  bot.susp), bot.susp)
  } 
  
  # this sets the threshold for a bot warning, depending if they entered the IP argument or not. 
  if(missing(IP)) {
    outputs <- ifelse(bot.susp >= 1, 1, 0)
  } else if(missing(Latitude)) {
    outputs <- ifelse(bot.susp >= 1, 1, 0)
  }  else{
    outputs <- ifelse(bot.susp >= 1, 1, 0)
  }  
  
  return(outputs)
  
} 