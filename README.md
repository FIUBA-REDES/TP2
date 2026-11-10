# TP2


## TESTS
Para correr los tests, debemos usar el path de POX, en el ejemplo esta el arp_manager_test.py que hace las pruebas unitarias de los casos, siendo estos mockeados para no depender de mininet.

PYTHONPATH=pox python3 -m unittest discover -s tests -p 'arp_manager_test.py' -v