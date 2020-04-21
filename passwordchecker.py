import requests #allows access to api
import hashlib #allows us to use SHA1 hashing
import sys #use to get arguments

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char #the first part is the website url for the api and next part is the first 5 characters of the sha1 version of password 
    res = requests.get(url)
    if res.status_code != 200: #if its not 200 then the api request failed
        raise RuntimeError(f"Error fetching: {res.status_code}, check the api and try again")
    return res

def pwn_api_check(password):
    #check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper() #this is the standard way of encoding the password to sha1 password
    first5_char, tail = sha1password[:5], sha1password[5:] #we get the first 5 characters because this is what is being sent to the api
    response = request_api_data(first5_char) #api returns all the passwords that have the first 5 characters of the sha1password
    return get_number_of_leaks(response, tail)

def get_number_of_leaks(hashes, hash_to_check):
    '''
    The api returns the sha1passwords with the same first five characters and the number of times it was hacked in this format:
    ASDFGGHJFKDJDJSFJKJ:10 <-- example of how it is returned
    ASJHGHJGLKHHKHLKHKK:12

    So we use the splitlines() function to seperate all the passwords and their counts and input it into a list
    Then this list is further split by the split() function so that everytime it sees a : it creates a list of the password and the count
    ex: [ASADSDASFJHKASJFHSKJ, 12]
    we then loop the entire list to find the matching password and return the count

    '''
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def print_response(response):
    print(response.text) #returns all the hashes that uses the first 5 characters also returns how many times it got hacked
    #this function is used for testing

def main(args):
    for password in args:
        count = pwn_api_check(password)
        if count:
            print(f'{password} was found {count} times... change your password!')
        else:
            print(f'{password} was NOT found. Safe!')    
    return 'done!'

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))